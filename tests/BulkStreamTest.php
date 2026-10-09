<?php

declare(strict_types=1);

namespace IPScanner\Tests;

use IPScanner\Exception\RateLimitException;

final class BulkStreamTest extends TestCase
{
    public function testStreamsEventsWithDefaults(): void
    {
        $this->transport->push(200, implode("\n", [
            '{"type":"meta","total":3,"processed":1,"metered":3}',
            '{"type":"result","input":"1.2.3.4","ip":"1.2.3.4","verdict":"clean","score":98,"grade":"S"}',
            '{"type":"error","index":1,"input":"10.0.0.1","reason":"reserved","message":"Private range"}',
            '{"type":"result","index":2,"ip":"5.6.7.8","anonymized":true,"confidence":0.8}',
            '{"type":"done","reason":"complete","processed":2,"failed":1,"total":3}',
        ]), ['Content-Type' => 'application/x-ndjson']);

        $events = iterator_to_array($this->client()->bulk->stream(ips: ['1.2.3.4', '10.0.0.1', '5.6.7.8']), false);

        $request = $this->lastRequest();
        $this->assertSame('https://ipscanner.io/v1/ip/bulk', $request['url']);
        $this->assertSame(300.0, $request['timeout']);
        $this->assertSame('{"ips":["1.2.3.4","10.0.0.1","5.6.7.8"]}', $request['body']);

        $this->assertCount(5, $events);
        $this->assertSame('meta', $events[0]['type']);
        $this->assertSame(0, $events[0]['failed']);
        $this->assertSame(0, $events[1]['index']);
        $this->assertSame(98, $events[1]['score']);
        $this->assertFalse($events[1]['anonymized']);
        $this->assertSame('', $events[1]['asn']);
        $this->assertSame(1, $events[2]['index']);
        $this->assertSame('reserved', $events[2]['reason']);
        $this->assertSame(0, $events[2]['score']);
        $this->assertTrue($events[3]['anonymized']);
        $this->assertSame('done', $events[4]['type']);
        $this->assertTrue($events[4]['complete']);
        $this->assertArrayNotHasKey('complete', $events[1]);
    }

    public function testDoneIsIncompleteWhenDeadlineHit(): void
    {
        $this->transport->push(200, '{"type":"done","reason":"complete","processed":10,"total":50}');

        $events = iterator_to_array($this->client()->bulk->stream(input: "1.2.3.4\n5.6.7.8"), false);

        $this->assertSame(['input' => "1.2.3.4\n5.6.7.8"], $this->transport->lastBody());
        $this->assertFalse($events[0]['complete']);
    }

    public function testDoneIsIncompleteOnQuota(): void
    {
        $this->transport->push(200, '{"type":"done","reason":"quota_exceeded","processed":5,"failed":0,"total":5}');

        $events = iterator_to_array($this->client()->bulk->stream(ips: ['1.2.3.4']), false);

        $this->assertFalse($events[0]['complete']);
    }

    public function testPreStreamErrorThrows(): void
    {
        $this->transport->push(429, ['error' => 'rate_limit_exceeded', 'reason' => 'monthly_quota', 'message' => 'Quota used', 'retryAfter' => 10]);

        try {
            iterator_to_array($this->client()->bulk->stream(ips: ['1.2.3.4']));
            $this->fail('Expected an exception');
        } catch (RateLimitException $e) {
            $this->assertSame('monthly_quota', $e->reason);
            $this->assertSame(10, $e->retryAfter);
        }
    }

    public function testLockedResultLineTreatsNullAsMissing(): void
    {
        $this->transport->push(200, implode("\n", [
            '{"type":"meta","total":1,"metered":1,"planRequired":"Starter"}',
            '{"type":"result","ip":"1.2.3.4","classification":"vpn","score":null,"grade":null,"verdict":null,"vpnProvider":null,"locked":["score","grade","verdict","vpnProvider"],"extra":true}',
            '{"type":"result","index":1,"ip":"5.6.7.8","classification":"vpn","vpnProvider":"Mullvad","score":40}',
            '{"type":"done","reason":"complete","processed":2,"total":2}',
        ]));

        $events = iterator_to_array($this->client()->bulk->stream(ips: ['1.2.3.4', '5.6.7.8']), false);

        $this->assertSame('Starter', $events[0]['planRequired']);
        $this->assertSame([], $events[0]['locked']);
        $this->assertSame(0, $events[1]['score']);
        $this->assertSame('', $events[1]['grade']);
        $this->assertSame('', $events[1]['verdict']);
        $this->assertSame('', $events[1]['vpnProvider']);
        $this->assertSame(['score', 'grade', 'verdict', 'vpnProvider'], $events[1]['locked']);
        $this->assertTrue($events[1]['extra']);
        $this->assertSame('Mullvad', $events[2]['vpnProvider']);
        $this->assertSame('', $events[2]['planRequired']);
        $this->assertTrue($events[3]['complete']);
    }
}
