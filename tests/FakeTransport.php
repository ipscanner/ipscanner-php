<?php

declare(strict_types=1);

namespace IPScanner\Tests;

use IPScanner\Exception\ConnectionException;
use IPScanner\Http\Response;
use IPScanner\Http\StreamResponse;
use IPScanner\Http\Transport;

final class FakeTransport implements Transport
{
    /** @var list<array{method: string, url: string, headers: array<string, string>, body: ?string, timeout: float}> */
    public array $requests = [];

    /** @var list<Response|ConnectionException> */
    private array $queue = [];

    public function push(int $status, mixed $body = null, array $headers = []): self
    {
        $raw = is_string($body) ? $body : (string) json_encode($body);
        $this->queue[] = new Response($status, $headers, $raw);
        return $this;
    }

    public function pushError(ConnectionException $e): self
    {
        $this->queue[] = $e;
        return $this;
    }

    public function request(string $method, string $url, array $headers, ?string $body, float $timeout): Response
    {
        $this->requests[] = compact('method', 'url', 'headers', 'body', 'timeout');
        $next = array_shift($this->queue);
        if ($next === null) {
            throw new \LogicException('No response queued');
        }
        if ($next instanceof ConnectionException) {
            throw $next;
        }
        return $next;
    }

    public function stream(string $method, string $url, array $headers, ?string $body, float $timeout): StreamResponse
    {
        $response = $this->request($method, $url, $headers, $body, $timeout);
        $lines = array_values(array_filter(explode("\n", $response->body), static fn ($l) => trim($l) !== ''));
        return new StreamResponse($response->status, $response->headers, $lines);
    }

    /**
     * @return array<mixed>
     */
    public function lastBody(): array
    {
        $last = end($this->requests);
        return json_decode((string) $last['body'], true);
    }
}
