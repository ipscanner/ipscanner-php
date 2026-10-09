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

    public function testEdgeCheck(): void
    {
        $this->transport->push(200, [
            'class' => 'vpn',
            'agent' => ['class' => 'human', 'confidence' => 0.7, 'action' => 'allow', 'signals' => ['scripted_client' => '']],
            'network' => [
                'networkClass' => 'vpn',
                'anonymized' => true,
                'riskScore' => 80,
                'provider' => 'M247',
                'vpnProvider' => 'Mullvad',
                'evidence' => ['vpn_server_list'],
                'asn' => 9009,
            ],
            'site' => ['id' => 'site_1', 'mode' => 'enforce', 'policyVersion' => 3],
        ]);

        $result = $this->client()->edge->check(ip: '1.2.3.4', site: 'site_1', userAgent: 'Mozilla/5.0', headlessFlags: ['webdriver' => true]);

        $request = $this->lastRequest();
        $this->assertSame('POST', $request['method']);
        $this->assertSame('https://ipscanner.io/v1/edge/check', $request['url']);
        $this->assertSame('Bearer sk_test', $request['headers']['Authorization']);
        $this->assertSame([
            'site' => 'site_1',
            'ip' => '1.2.3.4',
            'user_agent' => 'Mozilla/5.0',
            'headless_flags' => ['webdriver' => true],
        ], $this->transport->lastBody());
        $this->assertSame('vpn', $result['class']);
        $this->assertSame('Mullvad', $result['network']['vpnProvider']);
        $this->assertSame(['vpn_server_list'], $result['network']['evidence']);
        $this->assertSame(9009, $result['network']['asn']);
        $this->assertSame('enforce', $result['site']['mode']);
    }

    public function testEdgeCheckLocked(): void
    {
        $this->transport->push(200, [
            'class' => 'relay',
            'agent' => null,
            'network' => ['networkClass' => 'relay', 'anonymized' => true, 'riskScore' => 20, 'provider' => null, 'vpnProvider' => null],
            'site' => null,
            'degraded' => ['agent'],
            'locked' => ['network.provider', 'network.vpnProvider'],
            'planRequired' => 'Starter',
        ]);

        $result = $this->client()->edge->check(ip: '1.2.3.4');

        $this->assertSame('{"ip":"1.2.3.4"}', $this->lastRequest()['body']);
        $this->assertNull($result['agent']);
        $this->assertNull($result['site']);
        $this->assertNull($result['network']['provider']);
        $this->assertNull($result['network']['vpnProvider']);
        $this->assertSame(['network.provider', 'network.vpnProvider'], $result['locked']);
        $this->assertSame('Starter', $result['planRequired']);
    }

    public function testSitesPolicy(): void
    {
        $this->transport->push(200, [
            'site' => 'site/1',
            'mode' => 'monitor',
            'policy' => ['ai_agent' => 'flag', 'malicious_automation' => 'block'],
            'version' => 2,
            'updatedAt' => '2026-10-01T12:00:00.123456789Z',
        ]);

        $result = $this->client()->sites->policy('site/1');

        $request = $this->lastRequest();
        $this->assertSame('GET', $request['method']);
        $this->assertSame('https://ipscanner.io/v1/sites/site%2F1/policy', $request['url']);
        $this->assertSame('Bearer sk_test', $request['headers']['Authorization']);
        $this->assertSame('block', $result['policy']['malicious_automation']);
        $this->assertSame(2, $result['version']);
    }

    public function testGateVerifySendsNoAuthorization(): void
    {
        $this->transport->push(200, [
            'success' => true,
            'class' => 'human',
            'action' => 'allow',
            'mode' => 'enforce',
            'confidence' => 0.9,
            'network' => ['classification' => 'vpn', 'anonymized' => true, 'provider' => null, 'vpn_provider' => null],
            'signals' => [],
            'hostname' => 'example.com',
            'issued_at' => '2026-10-09T10:00:00Z',
            'ip_match' => true,
            'locked' => ['network.provider', 'network.vpn_provider'],
            'planRequired' => 'Starter',
        ]);

        $result = $this->client()->gate->verify(secret: 'gs_secret', token: 'tok_1', remoteIp: '1.2.3.4');

        $request = $this->lastRequest();
        $this->assertSame('POST', $request['method']);
        $this->assertSame('https://ipscanner.io/v1/gate/verify', $request['url']);
        $this->assertArrayNotHasKey('Authorization', $request['headers']);
        $this->assertSame('application/json', $request['headers']['Content-Type']);
        $this->assertSame('{"secret":"gs_secret","token":"tok_1","remote_ip":"1.2.3.4"}', $request['body']);
        $this->assertTrue($result['success']);
        $this->assertNull($result['network']['vpn_provider']);
        $this->assertSame(['network.provider', 'network.vpn_provider'], $result['locked']);
    }

    public function testGateVerifyOmitsRemoteIp(): void
    {
        $this->transport->push(200, ['success' => true]);

        $this->client()->gate->verify('gs_secret', 'tok_1');

        $this->assertSame(['secret' => 'gs_secret', 'token' => 'tok_1'], $this->transport->lastBody());
    }

    public function testLockedLookupDecodesNulls(): void
    {
        $this->transport->push(200, [
            'target' => ['raw' => '1.2.3.4', 'kind' => 'ipv4', 'ip' => '1.2.3.4'],
            'verdict' => ['classification' => 'vpn', 'anonymized' => true, 'confidence' => 0.95, 'method' => 'range', 'evidence' => ['vpn_range', 'vpn_operator']],
            'purity' => null,
            'networkClass' => 'vpn',
            'isVpn' => true,
            'provider' => null,
            'vpnProvider' => null,
            'geo' => ['country' => 'Sweden', 'latitude' => null, 'longitude' => null, 'postalCode' => null, 'accuracyRadius' => null],
            'newField' => ['nested' => 1],
            'locked' => ['purity', 'provider', 'vpnProvider', 'geo.latitude', 'geo.longitude', 'geo.postalCode', 'geo.accuracyRadius'],
            'planRequired' => 'Starter',
        ]);

        $result = $this->client()->ip->lookup('1.2.3.4');

        $this->assertNull($result['purity']);
        $this->assertNull($result['vpnProvider']);
        $this->assertNull($result['geo']['latitude']);
        $this->assertSame(['vpn_range', 'vpn_operator'], $result['verdict']['evidence']);
        $this->assertContains('geo.accuracyRadius', $result['locked']);
        $this->assertSame('Starter', $result['planRequired']);
        $this->assertSame(['nested' => 1], $result['newField']);
    }

    public function testLookupHostnameWhoisStatus(): void
    {
        $this->transport->push(200, [
            'target' => ['raw' => 'example.com', 'kind' => 'hostname', 'ip' => '93.184.215.14', 'hostname' => 'example.com'],
            'networkClass' => 'relay',
            'vpnProvider' => 'Mullvad',
            'whoisStatus' => 'timeout',
            'degraded' => ['whois'],
        ]);

        $result = $this->client()->ip->lookup('example.com');

        $this->assertSame('relay', $result['networkClass']);
        $this->assertSame('Mullvad', $result['vpnProvider']);
        $this->assertSame('timeout', $result['whoisStatus']);
        $this->assertArrayNotHasKey('whois', $result);
    }

    public function testWhoisUnavailableIsNotAnError(): void
    {
        $this->transport->push(200, [
            'domain' => 'example.com',
            'registrar' => '',
            'registeredOn' => '',
            'expiresOn' => '',
            'lastUpdated' => '',
            'nameservers' => [],
            'status' => [],
            'privacyProtection' => false,
            'whoisStatus' => 'unavailable',
        ]);

        $result = $this->client()->ip->whois('example.com');

        $this->assertSame('unavailable', $result['whoisStatus']);
        $this->assertSame([], $result['nameservers']);
    }

    public function testVpnProviderAndEvidence(): void
    {
        $this->transport->push(200, [
            'ip' => '1.2.3.4',
            'isVpn' => true,
            'networkClass' => 'vpn',
            'provider' => 'M247',
            'vpnProvider' => 'Proton VPN',
            'evidence' => ['vpn_server_list', 'some_future_value'],
        ]);

        $result = $this->client()->ip->vpn('1.2.3.4');

        $this->assertSame('Proton VPN', $result['vpnProvider']);
        $this->assertSame(['vpn_server_list', 'some_future_value'], $result['evidence']);
    }

    public function testLockedBulkCheckRow(): void
    {
        $this->transport->push(200, [
            'submitted' => 1,
            'unique' => 1,
            'duplicates' => 0,
            'invalid' => [],
            'summary' => (object) [],
            'results' => [[
                'input' => '1.2.3.4',
                'ip' => '1.2.3.4',
                'score' => null,
                'grade' => null,
                'verdict' => null,
                'classification' => 'vpn',
                'confidence' => 0.9,
                'anonymized' => true,
                'vpnProvider' => null,
                'deductions' => null,
                'locked' => ['score', 'grade', 'verdict', 'deductions', 'vpnProvider'],
            ]],
            'planRequired' => 'Starter',
        ]);

        $result = $this->client()->bulk->check(ips: ['1.2.3.4']);

        $row = $result['results'][0];
        $this->assertNull($row['score']);
        $this->assertNull($row['deductions']);
        $this->assertNull($row['vpnProvider']);
        $this->assertSame(['score', 'grade', 'verdict', 'deductions', 'vpnProvider'], $row['locked']);
        $this->assertSame([], $result['summary']);
        $this->assertSame('Starter', $result['planRequired']);
    }
}
