<?php

declare(strict_types=1);

namespace IPScanner\Tests;

final class EmailTest extends TestCase
{
    public function testEmailCheckPostsWithTheKey(): void
    {
        $this->transport->push(200, [
            'email' => 'jane@outlok.com',
            'status' => 'risky',
            'reason' => 'typo',
            'suggestion' => 'jane@outlook.com',
            'domain' => 'outlok.com',
            'checks' => ['syntax' => true, 'mx' => null, 'disposable' => false, 'role' => false, 'freeProvider' => false],
            'mailbox' => 'not_checked',
        ]);

        $result = $this->client()->email->check('jane@outlok.com');

        $request = $this->lastRequest();
        $this->assertSame('POST', $request['method']);
        $this->assertSame('https://ipscanner.io/v1/email/check', $request['url']);
        $this->assertSame('Bearer sk_test', $request['headers']['Authorization']);
        $this->assertSame('ipscanner-php/0.3.1', $request['headers']['User-Agent']);
        $this->assertSame('{"email":"jane@outlok.com"}', $request['body']);
        $this->assertSame('jane@outlook.com', $result['suggestion']);
        $this->assertNull($result['checks']['mx']);
    }

    public function testGateVerifySendsTheEmail(): void
    {
        $this->transport->push(200, [
            'success' => true,
            'action' => 'block',
            'email' => ['status' => 'risky', 'reason' => 'disposable', 'suggestion' => null, 'domain' => 'mailinator.com', 'action' => 'block'],
        ]);

        $result = $this->client()->gate->verify('gs_secret', 'tok_1', email: 'x@mailinator.com');

        $this->assertSame(['secret' => 'gs_secret', 'token' => 'tok_1', 'email' => 'x@mailinator.com'], $this->transport->lastBody());
        $this->assertSame('block', $result['email']['action']);
    }

    public function testProxyLockedPurityCount(): void
    {
        $this->transport->push(200, [
            'ip' => '5.6.7.8',
            'purity' => null,
            'deductionCount' => 3,
            'locked' => ['purity', 'provider', 'vpnProvider'],
            'planRequired' => 'Starter',
        ]);

        $result = $this->client()->ip->proxy('5.6.7.8');

        $this->assertNull($result['purity']);
        $this->assertSame(3, $result['deductionCount']);
    }
}
