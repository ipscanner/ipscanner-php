<?php

declare(strict_types=1);

namespace IPScanner\Http;

use IPScanner\Exception\ConnectionException;
use IPScanner\Exception\TimeoutException;

interface Transport
{
    /**
     * Sends a request and returns the full response.
     *
     * @param array<string, string> $headers
     * @throws ConnectionException
     * @throws TimeoutException
     */
    public function request(string $method, string $url, array $headers, ?string $body, float $timeout): Response;

    /**
     * Sends a request and returns once the status and headers are known; the body is read line by line.
     *
     * @param array<string, string> $headers
     * @throws ConnectionException
     * @throws TimeoutException
     */
    public function stream(string $method, string $url, array $headers, ?string $body, float $timeout): StreamResponse;
}
