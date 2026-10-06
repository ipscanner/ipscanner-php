<?php

declare(strict_types=1);

namespace IPScanner;

use Generator;
use IPScanner\Exception\ApiException;
use IPScanner\Exception\AuthenticationException;
use IPScanner\Exception\ConnectionException;
use IPScanner\Exception\NotFoundException;
use IPScanner\Exception\RateLimitException;
use IPScanner\Http\CurlTransport;
use IPScanner\Http\Response;
use IPScanner\Http\Transport;
use IPScanner\Resource\Account;
use IPScanner\Resource\Agentscan;
use IPScanner\Resource\AsnDirectory;
use IPScanner\Resource\Bulk;
use IPScanner\Resource\Crawlers;
use IPScanner\Resource\Ip;
use IPScanner\Resource\Provenance;
use JsonException;

final class Client
{
    public const VERSION = '0.1.0';
    public const DEFAULT_BASE_URL = 'https://ipscanner.io';
    public const STREAM_TIMEOUT = 300.0;

    private const RETRY_STATUSES = [502, 503, 504];

    private const RATE_LIMIT_HEADERS = [
        'x-ratelimit-meter' => 'meter',
        'x-ratelimit-limit' => 'limit',
        'x-ratelimit-remaining' => 'remaining',
        'x-ratelimit-reset' => 'reset',
        'x-ratelimit-daily-limit' => 'dailyLimit',
        'x-ratelimit-daily-remaining' => 'dailyRemaining',
        'x-ratelimit-daily-reset' => 'dailyReset',
        'x-ratelimit-hourly-limit' => 'hourlyLimit',
        'x-ratelimit-hourly-remaining' => 'hourlyRemaining',
        'x-ratelimit-hourly-reset' => 'hourlyReset',
        'x-ratelimit-usage-percent' => 'usagePercent',
        'x-quota-upgrade-hint' => 'upgradeHint',
        'x-quota-upgrade-url' => 'upgradeUrl',
        'x-quota-upgrade-plan' => 'upgradePlan',
        'retry-after' => 'retryAfter',
    ];

    private const STATUS_TEXT = [
        400 => 'Bad Request',
        401 => 'Unauthorized',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        413 => 'Payload Too Large',
        429 => 'Too Many Requests',
        500 => 'Internal Server Error',
        502 => 'Bad Gateway',
        503 => 'Service Unavailable',
        504 => 'Gateway Timeout',
    ];

    public readonly Ip $ip;
    public readonly Bulk $bulk;
    public readonly Agentscan $agentscan;
    public readonly Provenance $provenance;
    public readonly Account $account;
    public readonly AsnDirectory $asnDirectory;
    public readonly Crawlers $crawlers;

    private readonly ?string $apiKey;
    private readonly string $baseUrl;
    private readonly Transport $transport;

    public function __construct(
        ?string $apiKey = null,
        ?string $baseUrl = null,
        private readonly float $timeout = 30.0,
        private readonly int $maxRetries = 2,
        ?Transport $transport = null,
    ) {
        $apiKey ??= self::env('IPSCANNER_API_KEY');
        $this->apiKey = $apiKey === '' ? null : $apiKey;
        $this->baseUrl = rtrim($baseUrl ?? self::env('IPSCANNER_API_URL') ?? self::DEFAULT_BASE_URL, '/');
        $this->transport = $transport ?? new CurlTransport();

        $this->ip = new Ip($this);
        $this->bulk = new Bulk($this);
        $this->agentscan = new Agentscan($this);
        $this->provenance = new Provenance($this);
        $this->account = new Account($this);
        $this->asnDirectory = new AsnDirectory($this);
        $this->crawlers = new Crawlers($this);
    }

    /**
     * Sends a request to the API and returns the decoded JSON body.
     *
     * @param array<string, scalar|null> $query
     * @param array<string, mixed>|null $body
     * @return array<mixed>
     */
    public function request(string $method, string $path, array $query = [], ?array $body = null): array
    {
        $response = $this->send($method, $path, $query, $body);
        return $this->decode($response->body);
    }

    /**
     * Sends a request to the API and returns the raw response body.
     *
     * @param array<string, scalar|null> $query
     * @param array<string, mixed>|null $body
     */
    public function requestRaw(string $method, string $path, array $query = [], ?array $body = null, string $accept = '*/*'): string
    {
        return $this->send($method, $path, $query, $body, $accept)->body;
    }

    /**
     * Sends a POST request and yields each decoded NDJSON line.
     *
     * @param array<string, mixed> $body
     * @return Generator<int, array<mixed>>
     */
    public function streamLines(string $path, array $body): Generator
    {
        $response = $this->transport->stream(
            'POST',
            $this->url($path, []),
            $this->headers(true, 'application/x-ndjson'),
            $this->encode($body),
            self::STREAM_TIMEOUT,
        );

        if ($response->status < 200 || $response->status >= 300) {
            throw $this->error($response->toResponse());
        }

        foreach ($response->lines() as $line) {
            yield $this->decode($line);
        }
    }

    /**
     * @param array<string, scalar|null> $query
     * @param array<string, mixed>|null $body
     */
    private function send(string $method, string $path, array $query, ?array $body, string $accept = 'application/json'): Response
    {
        $url = $this->url($path, $query);
        $headers = $this->headers($body !== null, $accept);
        $payload = $body === null ? null : $this->encode($body);
        $retries = $method === 'GET' ? max(0, $this->maxRetries) : 0;

        for ($attempt = 0; ; $attempt++) {
            try {
                $response = $this->transport->request($method, $url, $headers, $payload, $this->timeout);
            } catch (ConnectionException $e) {
                if ($attempt >= $retries) {
                    throw $e;
                }
                $this->backoff($attempt);
                continue;
            }

            if (in_array($response->status, self::RETRY_STATUSES, true) && $attempt < $retries) {
                $this->backoff($attempt);
                continue;
            }

            if ($response->status < 200 || $response->status >= 300) {
                throw $this->error($response);
            }

            return $response;
        }
    }

    /**
     * @param array<string, scalar|null> $query
     */
    private function url(string $path, array $query): string
    {
        $params = [];
        foreach ($query as $key => $value) {
            if ($value === null || $value === '') {
                continue;
            }
            $params[$key] = is_bool($value) ? ($value ? 'true' : 'false') : (string) $value;
        }

        $url = $this->baseUrl . $path;
        if ($params !== []) {
            $url .= '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
        }
        return $url;
    }

    /**
     * @return array<string, string>
     */
    private function headers(bool $hasBody, string $accept): array
    {
        $headers = [
            'Accept' => $accept,
            'User-Agent' => 'ipscanner-php/' . self::VERSION,
        ];
        if ($hasBody) {
            $headers['Content-Type'] = 'application/json';
        }
        if ($this->apiKey !== null) {
            $headers['Authorization'] = 'Bearer ' . $this->apiKey;
        }
        return $headers;
    }

    /**
     * @param array<string, mixed> $body
     */
    private function encode(array $body): string
    {
        return json_encode((object) $body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * @return array<mixed>
     */
    private function decode(string $body): array
    {
        if (trim($body) === '') {
            return [];
        }
        try {
            $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new ConnectionException('Invalid JSON in response: ' . $e->getMessage(), 0, $e);
        }
        return is_array($data) ? $data : [];
    }

    private function error(Response $response): ApiException
    {
        $status = $response->status;
        $data = null;
        try {
            $data = json_decode($response->body, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
        }

        if (is_array($data) && isset($data['error']) && is_string($data['error'])) {
            $code = $data['error'];
            $message = is_string($data['message'] ?? null) ? $data['message'] : $code;
            $details = is_array($data['details'] ?? null) ? $data['details'] : null;
        } else {
            $data = [];
            $code = 'http_' . $status;
            $message = self::STATUS_TEXT[$status] ?? 'HTTP ' . $status;
            $details = null;
        }

        $args = [$message, $status, $code, $details, $response->body, $response->headers];

        return match (true) {
            $status === 401, $status === 403 => new AuthenticationException(...$args),
            $status === 404 => new NotFoundException(...$args),
            $status === 429 => $this->rateLimitError($args, $data, $response),
            default => new ApiException(...$args),
        };
    }

    /**
     * @param array{string, int, string, array<string, mixed>|null, string, array<string, string>} $args
     * @param array<mixed> $data
     */
    private function rateLimitError(array $args, array $data, Response $response): RateLimitException
    {
        $rateLimit = [];
        foreach (self::RATE_LIMIT_HEADERS as $header => $key) {
            $value = $response->header($header);
            if ($value !== null) {
                $rateLimit[$key] = is_numeric($value) && ctype_digit($value) ? (int) $value : $value;
            }
        }

        $retryAfter = self::int($data['retryAfter'] ?? null);
        if ($retryAfter === null && is_numeric($response->header('retry-after'))) {
            $retryAfter = (int) $response->header('retry-after');
        }

        $upgrade = is_array($data['upgrade'] ?? null) ? $data['upgrade'] : [];
        $upgradeUrl = self::str($upgrade['url'] ?? null) ?? $response->header('x-quota-upgrade-url');

        return new RateLimitException(
            ...$args,
            reason: self::str($data['reason'] ?? null),
            retryAfter: $retryAfter,
            resetAt: self::str($data['resetAt'] ?? null),
            limit: self::int($data['limit'] ?? null),
            usage: self::int($data['usage'] ?? null),
            remaining: self::int($data['remaining'] ?? null),
            needed: self::int($data['needed'] ?? null),
            plan: self::str($data['plan'] ?? null),
            upgradeUrl: $upgradeUrl,
            rateLimit: $rateLimit,
        );
    }

    private function backoff(int $attempt): void
    {
        usleep((int) (500000 * (2 ** $attempt)));
    }

    private static function env(string $name): ?string
    {
        $value = getenv($name);
        return $value === false || $value === '' ? null : $value;
    }

    private static function int(mixed $value): ?int
    {
        return is_int($value) || is_float($value) ? (int) $value : null;
    }

    private static function str(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
