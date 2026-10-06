<?php

declare(strict_types=1);

namespace IPScanner\Http;

final class StreamResponse
{
    /** @var array<string, string> */
    public readonly array $headers;

    /**
     * @param array<string, string> $headers
     * @param iterable<string> $lines
     */
    public function __construct(
        public readonly int $status,
        array $headers,
        private readonly iterable $lines,
    ) {
        $this->headers = array_change_key_case($headers, CASE_LOWER);
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    /**
     * @return iterable<string>
     */
    public function lines(): iterable
    {
        return $this->lines;
    }

    public function toResponse(): Response
    {
        $body = '';
        foreach ($this->lines as $line) {
            $body .= $line . "\n";
        }
        return new Response($this->status, $this->headers, rtrim($body, "\n"));
    }
}
