<?php

declare(strict_types=1);

namespace IPScanner\Tests;

final class ResourceTest extends TestCase
{
    public function testAgentscanCheckSendsSnakeCase(): void
    {
        $this->transport->push(200, ['class' => 'human', 'confidence' => 0.9, 'action' => 'allow', 'signals' => []]);

        $this->client()->agentscan->check(
            ip: '1.2.3.4',
            userAgent: 'Mozilla/5.0',
            headers: ['accept-language' => 'en'],
            headlessFlags: ['webdriver' => false],
            requestId: 'req_1',
        );

        $this->assertSame('https://ipscanner.io/v1/agentscan/check', $this->lastRequest()['url']);
        $this->assertSame([
            'ip' => '1.2.3.4',
            'user_agent' => 'Mozilla/5.0',
            'headers' => ['accept-language' => 'en'],
            'headless_flags' => ['webdriver' => false],
            'request_id' => 'req_1',
        ], $this->transport->lastBody());
    }

    public function testEmptyMapsEncodeAsObjects(): void
    {
        $this->transport->push(200, []);

        $this->client()->agentscan->check(ip: '1.2.3.4', headers: []);

        $this->assertSame('{"ip":"1.2.3.4","headers":{}}', $this->lastRequest()['body']);
    }

    public function testAgentscanSelfSendsEmptyObject(): void
    {
        $this->transport->push(200, ['metered' => false]);

        $this->client()->agentscan->selfCheck();

        $this->assertSame('{}', $this->lastRequest()['body']);
    }

    public function testAgentscanBatchNumbersLines(): void
    {
        $this->transport->push(200, ['submitted' => 2]);

        $this->client()->agentscan->batch([
            ['ip' => '1.2.3.4', 'userAgent' => 'curl/8'],
            ['line' => 9, 'ip' => '5.6.7.8'],
        ]);

        $this->assertSame(['lines' => [
            ['ip' => '1.2.3.4', 'user_agent' => 'curl/8', 'line' => 1],
            ['line' => 9, 'ip' => '5.6.7.8'],
        ]], $this->transport->lastBody());
    }

    public function testAgentscanVerify(): void
    {
        $this->transport->push(200, ['outcome' => 'verified']);

        $this->client()->agentscan->verify(ip: '66.249.66.1', bot: 'googlebot');

        $this->assertSame(['ip' => '66.249.66.1', 'bot' => 'googlebot'], $this->transport->lastBody());
    }

    public function testProvenanceCheckSendsSnakeCase(): void
    {
        $this->transport->push(200, ['policy_action' => 'allow', 'attestation_id' => 7]);

        $result = $this->client()->provenance->check(
            ip: '1.2.3.4',
            claimedJurisdiction: 'GB',
            requestContext: ['path' => '/checkout'],
        );

        $this->assertSame([
            'ip' => '1.2.3.4',
            'claimed_jurisdiction' => 'GB',
            'request_context' => ['path' => '/checkout'],
        ], $this->transport->lastBody());
        $this->assertSame('allow', $result['policy_action']);
    }

    public function testProvenanceVerifyAnchoredPostsEmptyObject(): void
    {
        $this->transport->push(200, ['ok' => true]);

        $this->client()->provenance->verifyAnchored();

        $request = $this->lastRequest();
        $this->assertSame('POST', $request['method']);
        $this->assertSame('{}', $request['body']);
    }

    public function testProvenanceExportReturnsCsv(): void
    {
        $this->transport->push(200, "id,ts,ip\n1,2026-10-01T00:00:00Z,1.2.3.4\n", ['Content-Type' => 'text/csv']);

        $csv = $this->client()->provenance->export(from: '2026-10-01', to: new \DateTimeImmutable('2026-10-05T00:00:00Z'));

        $this->assertStringStartsWith('id,ts,ip', $csv);
        $this->assertSame(
            'https://ipscanner.io/v1/provenance/export?from=2026-10-01&to=2026-10-05T00%3A00%3A00%2B00%3A00',
            $this->lastRequest()['url'],
        );
        $this->assertSame('text/csv', $this->lastRequest()['headers']['Accept']);
    }

    public function testAsnDirectory(): void
    {
        $this->transport->push(200, [])->push(200, [])->push(200, []);

        $client = $this->client(null);
        $client->asnDirectory->get('AS15169');
        $this->assertSame('https://ipscanner.io/v1/asn/directory/15169', $this->lastRequest()['url']);

        $client->asnDirectory->top(top: 5, by: 'prefixes');
        $this->assertSame('https://ipscanner.io/v1/asn/directory?top=5&by=prefixes', $this->lastRequest()['url']);

        $client->asnDirectory->search('google cloud', limit: 3);
        $this->assertSame('https://ipscanner.io/v1/asn/directory?q=google%20cloud&limit=3', $this->lastRequest()['url']);
    }

    public function testAsnDirectoryRejectsGarbage(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->client()->asnDirectory->get('google');
    }
}
