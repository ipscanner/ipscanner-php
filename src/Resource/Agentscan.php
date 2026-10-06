<?php

declare(strict_types=1);

namespace IPScanner\Resource;

final class Agentscan extends Resource
{
    /**
     * Classifies a request as human, known bot, AI agent or malicious automation.
     *
     * @param array<string, string>|null $headers
     * @param array<string, bool>|null $headlessFlags
     * @return array<mixed>
     */
    public function check(
        string $ip,
        ?string $userAgent = null,
        ?string $ja4 = null,
        ?array $headers = null,
        ?array $headlessFlags = null,
        ?string $requestId = null,
    ): array {
        return $this->client->request('POST', '/v1/agentscan/check', body: self::compact([
            'ip' => $ip,
            'user_agent' => $userAgent,
            'ja4' => $ja4,
            'headers' => self::map($headers),
            'headless_flags' => self::map($headlessFlags),
            'request_id' => $requestId,
        ]));
    }

    /**
     * Classifies up to 25000 parsed log lines. Each line takes ip and optionally line, userAgent, ja4 and headers.
     *
     * @param array<array<string, mixed>> $lines
     * @return array<mixed>
     */
    public function batch(array $lines): array
    {
        $out = [];
        foreach (array_values($lines) as $i => $line) {
            if (array_key_exists('userAgent', $line)) {
                $line['user_agent'] = $line['userAgent'];
                unset($line['userAgent']);
            }
            if (isset($line['headers']) && is_array($line['headers'])) {
                $line['headers'] = (object) $line['headers'];
            }
            $out[] = self::compact($line) + ['line' => $i + 1];
        }

        return $this->client->request('POST', '/v1/agentscan/batch', body: ['lines' => $out]);
    }

    /**
     * Checks whether a crawler claim is genuine. Pass a crawler slug as $bot or a $userAgent.
     *
     * @return array<mixed>
     */
    public function verify(string $ip, ?string $bot = null, ?string $userAgent = null): array
    {
        return $this->client->request('POST', '/v1/agentscan/verify', body: self::compact([
            'ip' => $ip,
            'bot' => $bot,
            'user_agent' => $userAgent,
        ]));
    }

    /**
     * @return array<mixed>
     */
    public function allowlist(): array
    {
        return $this->client->request('GET', '/v1/agentscan/allowlist');
    }

    /**
     * Classifies the caller. Not metered.
     *
     * @param array<string, string>|null $headers
     * @return array<mixed>
     */
    public function selfCheck(?string $ip = null, ?string $userAgent = null, ?array $headers = null, ?string $ja4 = null): array
    {
        return $this->client->request('POST', '/v1/agentscan/self', body: self::compact([
            'ip' => $ip,
            'user_agent' => $userAgent,
            'headers' => self::map($headers),
            'ja4' => $ja4,
        ]));
    }
}
