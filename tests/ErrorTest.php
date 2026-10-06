<?php

declare(strict_types=1);

namespace IPScanner\Tests;

use IPScanner\Exception\ApiException;
use IPScanner\Exception\AuthenticationException;
use IPScanner\Exception\IPScannerException;
use IPScanner\Exception\NotFoundException;
use IPScanner\Exception\RateLimitException;

final class ErrorTest extends TestCase
{
    public function testUnauthorizedMapsToAuthenticationException(): void
    {
        $this->transport->push(401, ['error' => 'invalid_api_key', 'message' => 'Invalid API key']);

        try {
            $this->client()->account->limits();
            $this->fail('Expected an exception');
        } catch (AuthenticationException $e) {
            $this->assertSame(401, $e->status);
            $this->assertSame('invalid_api_key', $e->errorCode);
            $this->assertSame('Invalid API key', $e->getMessage());
            $this->assertInstanceOf(IPScannerException::class, $e);
        }
    }

    public function testForbiddenMapsToAuthenticationException(): void
    {
        $this->transport->push(403, ['error' => 'account_suspended', 'message' => 'Suspended']);

        $this->expectException(AuthenticationException::class);
        $this->client()->account->limits();
    }

    public function testNotFound(): void
    {
        $this->transport->push(404, ['error' => 'not_found', 'message' => 'No autonomous system']);

        $this->expectException(NotFoundException::class);
        $this->client()->asnDirectory->get('AS99999999');
    }

    public function testBadRequestKeepsDetails(): void
    {
        $this->transport->push(400, ['error' => 'bad_request', 'message' => 'Invalid', 'details' => ['invalid' => ['nope']]]);

        try {
            $this->client()->bulk->check(ips: ['nope']);
            $this->fail('Expected an exception');
        } catch (ApiException $e) {
            $this->assertSame(['invalid' => ['nope']], $e->details);
            $this->assertStringContainsString('bad_request', $e->body);
        }
    }

    public function testQuotaRateLimit(): void
    {
        $this->transport->push(429, [
            'error' => 'rate_limit_exceeded',
            'reason' => 'insufficient_for_batch',
            'message' => 'Not enough allowance',
            'meter' => 'request',
            'plan' => 'free',
            'limit' => 1000,
            'usage' => 990,
            'remaining' => 10,
            'needed' => 50,
            'resetDate' => '2026-11-01',
            'resetAt' => '2026-11-01T00:00:00Z',
            'retryAfter' => 3600,
            'softBlock' => false,
            'upgrade' => ['recommendedPlan' => 'starter', 'url' => 'https://ipscanner.io/pricing', 'message' => 'Upgrade'],
        ], ['X-RateLimit-Limit' => '1000', 'X-RateLimit-Remaining' => '10', 'X-RateLimit-Meter' => 'request']);

        try {
            $this->client()->bulk->check(ips: ['1.2.3.4']);
            $this->fail('Expected an exception');
        } catch (RateLimitException $e) {
            $this->assertSame(429, $e->status);
            $this->assertSame('rate_limit_exceeded', $e->errorCode);
            $this->assertSame('insufficient_for_batch', $e->reason);
            $this->assertSame(3600, $e->retryAfter);
            $this->assertSame('2026-11-01T00:00:00Z', $e->resetAt);
            $this->assertSame(1000, $e->limit);
            $this->assertSame(990, $e->usage);
            $this->assertSame(10, $e->remaining);
            $this->assertSame(50, $e->needed);
            $this->assertSame('free', $e->plan);
            $this->assertSame('https://ipscanner.io/pricing', $e->upgradeUrl);
            $this->assertSame(['meter' => 'request', 'limit' => 1000, 'remaining' => 10], $e->rateLimit);
        }
    }

    public function testRateLimitFallsBackToRetryAfterHeader(): void
    {
        $this->transport->push(429, ['error' => 'rate_limit_exceeded', 'message' => 'Slow down'], ['Retry-After' => '42']);

        try {
            $this->client(null)->ip->demo('1.2.3.4');
            $this->fail('Expected an exception');
        } catch (RateLimitException $e) {
            $this->assertSame(42, $e->retryAfter);
            $this->assertNull($e->reason);
            $this->assertSame(42, $e->rateLimit['retryAfter']);
        }
        $this->assertCount(1, $this->transport->requests);
    }

    public function testNonJsonErrorBody(): void
    {
        $this->transport->push(500, '<html>oops</html>');

        try {
            $this->client()->ip->lookup('1.2.3.4');
            $this->fail('Expected an exception');
        } catch (ApiException $e) {
            $this->assertSame('http_500', $e->errorCode);
            $this->assertSame('Internal Server Error', $e->getMessage());
            $this->assertSame('<html>oops</html>', $e->body);
        }
    }
}
