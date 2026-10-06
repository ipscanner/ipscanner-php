<?php

declare(strict_types=1);

namespace IPScanner\Tests;

use IPScanner\Client;
use PHPUnit\Framework\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected FakeTransport $transport;

    protected function setUp(): void
    {
        putenv('IPSCANNER_API_KEY');
        putenv('IPSCANNER_API_URL');
        $this->transport = new FakeTransport();
    }

    protected function client(?string $apiKey = 'sk_test', int $maxRetries = 2): Client
    {
        return new Client(apiKey: $apiKey, maxRetries: $maxRetries, transport: $this->transport);
    }

    /**
     * @return array{method: string, url: string, headers: array<string, string>, body: ?string, timeout: float}
     */
    protected function lastRequest(): array
    {
        $last = end($this->transport->requests);
        $this->assertNotFalse($last);
        return $last;
    }
}
