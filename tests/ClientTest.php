<?php

declare(strict_types=1);

namespace IPScanner\Tests;

use IPScanner\Client;
use IPScanner\Exception\ConnectionException;
use IPScanner\Exception\TimeoutException;

final class ClientTest extends TestCase
{
    public function testSendsAuthorizationHeaderWhenKeyIsSet(): void
    {
        $this->transport->push(200, ['ip' => '1.2.3.4', 'isVpn' => false]);

        $result = $this->client()->ip->vpn('1.2.3.4');

        $request = $this->lastRequest();
        $this->assertSame('GET', $request['method']);
        $this->assertSame('https://ipscanner.io/v1/vpn/1.2.3.4', $request['url']);
        $this->assertSame('Bearer sk_test', $request['headers']['Authorization']);
        $this->assertSame('ipscanner-php/0.1.0', $request['headers']['User-Agent']);
        $this->assertSame('application/json', $request['headers']['Accept']);
        $this->assertArrayNotHasKey('Content-Type', $request['headers']);
        $this->assertSame(['ip' => '1.2.3.4', 'isVpn' => false], $result);
    }

    public function testOmitsAuthorizationHeaderWithoutKey(): void
    {
        $this->transport->push(200, ['ipv4' => '1.2.3.4']);

        $this->client(null)->ip->myip();

        $this->assertArrayNotHasKey('Authorization', $this->lastRequest()['headers']);
    }

    public function testReadsKeyAndBaseUrlFromEnvironment(): void
    {
        putenv('IPSCANNER_API_KEY=sk_env');
        putenv('IPSCANNER_API_URL=http://localhost:8080/');
        $this->transport->push(200, ['crawlers' => [], 'count' => 0]);

        (new Client(transport: $this->transport))->crawlers->list();

        $request = $this->lastRequest();
        $this->assertSame('http://localhost:8080/v1/crawlers', $request['url']);
        $this->assertSame('Bearer sk_env', $request['headers']['Authorization']);
    }

    public function testEscapesIpv6PathSegments(): void
    {
        $this->transport->push(200, []);

        $this->client()->ip->geo('2001:db8::1');

        $this->assertSame('https://ipscanner.io/v1/geo/2001%3Adb8%3A%3A1', $this->lastRequest()['url']);
    }

    public function testPostSendsJsonBodyWithContentType(): void
    {
        $this->transport->push(200, ['target' => ['raw' => 'example.com']]);

        $this->client()->ip->lookup('example.com');

        $request = $this->lastRequest();
        $this->assertSame('POST', $request['method']);
        $this->assertSame('application/json', $request['headers']['Content-Type']);
        $this->assertSame('{"target":"example.com"}', $request['body']);
    }

    public function testQueryParametersSkipNulls(): void
    {
        $this->transport->push(200, ['events' => [], 'nextBefore' => 0]);

        $this->client()->ip->history(limit: 10, verdict: 'vpn');

        $this->assertSame('https://ipscanner.io/v1/ip/history?limit=10&verdict=vpn', $this->lastRequest()['url']);
    }

    public function testRetriesGetOnServiceUnavailable(): void
    {
        $this->transport->push(503, 'upstream down')->push(200, ['ok' => true, 'count' => 3, 'brokenAt' => 0]);

        $result = $this->client()->provenance->verify();

        $this->assertCount(2, $this->transport->requests);
        $this->assertTrue($result['ok']);
    }

    public function testRetriesGetOnConnectionError(): void
    {
        $this->transport->pushError(new TimeoutException('timed out'))->push(200, ['plan' => 'free']);

        $result = $this->client()->account->usage();

        $this->assertCount(2, $this->transport->requests);
        $this->assertSame('free', $result['plan']);
    }

    public function testGivesUpAfterMaxRetries(): void
    {
        $this->transport->pushError(new ConnectionException('refused'));

        $this->expectException(ConnectionException::class);
        try {
            $this->client(maxRetries: 0)->account->limits();
        } finally {
            $this->assertCount(1, $this->transport->requests);
        }
    }

    public function testDoesNotRetryPost(): void
    {
        $this->transport->push(503, 'upstream down');

        try {
            $this->client()->ip->lookup('1.2.3.4');
            $this->fail('Expected an exception');
        } catch (\IPScanner\Exception\ApiException $e) {
            $this->assertSame(503, $e->status);
            $this->assertSame('http_503', $e->errorCode);
            $this->assertSame('Service Unavailable', $e->getMessage());
        }
        $this->assertCount(1, $this->transport->requests);
    }
}
