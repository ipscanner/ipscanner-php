<?php

declare(strict_types=1);

namespace IPScanner\Tests;

use IPScanner\Exception\TimeoutException;
use IPScanner\Http\CurlTransport;
use PHPUnit\Framework\TestCase as BaseTestCase;

final class CurlTransportTest extends BaseTestCase
{
    /** @var resource|null */
    private static $server = null;
    private static string $base = '';

    public static function setUpBeforeClass(): void
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr((string) stream_socket_get_name($socket, false), strrpos((string) stream_socket_get_name($socket, false), ':') + 1);
        fclose($socket);

        $cmd = [PHP_BINARY, '-S', '127.0.0.1:' . $port, __DIR__ . '/fixtures/server.php'];
        self::$server = proc_open($cmd, [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        self::$base = 'http://127.0.0.1:' . $port;

        for ($i = 0; $i < 50; $i++) {
            $conn = @fsockopen('127.0.0.1', $port);
            if ($conn !== false) {
                fclose($conn);
                return;
            }
            usleep(100000);
        }
        self::markTestSkipped('Could not start the PHP built-in server');
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$server)) {
            proc_terminate(self::$server);
            proc_close(self::$server);
        }
    }

    public function testRequest(): void
    {
        $response = (new CurlTransport())->request(
            'POST',
            self::$base . '/echo',
            ['Authorization' => 'Bearer sk_test', 'Content-Type' => 'application/json'],
            '{"a":1}',
            5,
        );

        $this->assertSame(200, $response->status);
        $this->assertSame('1000', $response->header('X-RateLimit-Limit'));
        $this->assertSame(['method' => 'POST', 'auth' => 'Bearer sk_test', 'body' => '{"a":1}'], json_decode($response->body, true));
    }

    public function testErrorStatus(): void
    {
        $response = (new CurlTransport())->request('GET', self::$base . '/missing', [], null, 5);

        $this->assertSame(404, $response->status);
        $this->assertStringContainsString('not_found', $response->body);
    }

    public function testStreamYieldsLines(): void
    {
        $response = (new CurlTransport())->stream('POST', self::$base . '/stream', [], '{}', 5);

        $this->assertSame(200, $response->status);
        $this->assertSame('application/x-ndjson', $response->header('content-type'));
        $lines = iterator_to_array($response->lines(), false);
        $this->assertCount(4, $lines);
        $this->assertSame('{"type":"meta","total":2}', $lines[0]);
        $this->assertSame('{"type":"done","reason":"complete","processed":2,"total":2}', $lines[3]);
    }

    public function testTimeout(): void
    {
        $this->expectException(TimeoutException::class);
        (new CurlTransport())->request('GET', self::$base . '/slow', [], null, 0.5);
    }
}
