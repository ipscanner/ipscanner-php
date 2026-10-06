<?php

declare(strict_types=1);

namespace IPScanner\Http;

use CurlHandle;
use IPScanner\Exception\ConnectionException;
use IPScanner\Exception\TimeoutException;
use stdClass;

final class CurlTransport implements Transport
{
    public function request(string $method, string $url, array $headers, ?string $body, float $timeout): Response
    {
        $state = $this->state();
        $handle = $this->handle($method, $url, $headers, $body, $timeout, $state);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);

        $result = curl_exec($handle);
        if ($result === false) {
            throw $this->failure(curl_errno($handle), curl_error($handle));
        }

        return new Response($state->status, $state->headers, (string) $result);
    }

    public function stream(string $method, string $url, array $headers, ?string $body, float $timeout): StreamResponse
    {
        $state = $this->state();
        $handle = $this->handle($method, $url, $headers, $body, $timeout, $state);
        curl_setopt($handle, CURLOPT_WRITEFUNCTION, static function ($ch, string $data) use ($state): int {
            $state->buffer .= $data;
            return strlen($data);
        });

        $multi = curl_multi_init();
        curl_multi_add_handle($multi, $handle);

        $pump = function () use ($multi, $handle, $state): void {
            $active = 0;
            do {
                $code = curl_multi_exec($multi, $active);
            } while ($code === CURLM_CALL_MULTI_PERFORM);

            while (($info = curl_multi_info_read($multi)) !== false) {
                if ($info['handle'] !== $handle) {
                    continue;
                }
                $state->finished = true;
                if ($info['result'] !== CURLE_OK) {
                    throw $this->failure($info['result'], curl_error($handle) ?: curl_strerror($info['result']) ?? '');
                }
            }

            if (!$state->finished && curl_multi_select($multi, 1.0) === -1) {
                usleep(1000);
            }
        };

        $close = static function () use ($multi, $handle): void {
            curl_multi_remove_handle($multi, $handle);
            curl_multi_close($multi);
        };

        try {
            while (!$state->headersDone && !$state->finished) {
                $pump();
            }
        } catch (ConnectionException $e) {
            $close();
            throw $e;
        }

        $lines = (static function () use ($state, $pump, $close): \Generator {
            try {
                while (true) {
                    while (($pos = strpos($state->buffer, "\n")) !== false) {
                        $line = rtrim(substr($state->buffer, 0, $pos), "\r");
                        $state->buffer = substr($state->buffer, $pos + 1);
                        if ($line !== '') {
                            yield $line;
                        }
                    }
                    if ($state->finished) {
                        break;
                    }
                    $pump();
                }
                $rest = trim($state->buffer);
                $state->buffer = '';
                if ($rest !== '') {
                    yield $rest;
                }
            } finally {
                $close();
            }
        })();

        return new StreamResponse($state->status, $state->headers, $lines);
    }

    private function state(): stdClass
    {
        $state = new stdClass();
        $state->status = 0;
        $state->headers = [];
        $state->headersDone = false;
        $state->finished = false;
        $state->buffer = '';
        return $state;
    }

    /**
     * @param array<string, string> $headers
     */
    private function handle(string $method, string $url, array $headers, ?string $body, float $timeout, stdClass $state): CurlHandle
    {
        $handle = curl_init();
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }

        curl_setopt_array($handle, [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_TIMEOUT_MS => (int) ($timeout * 1000),
            CURLOPT_CONNECTTIMEOUT_MS => (int) (min($timeout, 10.0) * 1000),
            CURLOPT_ENCODING => '',
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use ($state): int {
                $trimmed = trim($line);
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $trimmed, $m) === 1) {
                    $state->status = (int) $m[1];
                    $state->headers = [];
                    $state->headersDone = false;
                } elseif ($trimmed === '') {
                    $state->headersDone = $state->status >= 200;
                } elseif (str_contains($trimmed, ':')) {
                    [$name, $value] = explode(':', $trimmed, 2);
                    $state->headers[strtolower(trim($name))] = trim($value);
                }
                return strlen($line);
            },
        ]);

        if ($body !== null) {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }

        return $handle;
    }

    private function failure(int $errno, string $message): ConnectionException
    {
        if ($errno === CURLE_OPERATION_TIMEDOUT) {
            return new TimeoutException('Request timed out: ' . $message);
        }
        return new ConnectionException('Connection failed: ' . $message);
    }
}
