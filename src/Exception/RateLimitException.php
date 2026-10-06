<?php

declare(strict_types=1);

namespace IPScanner\Exception;

class RateLimitException extends ApiException
{
    /**
     * @param array<string, mixed>|null $details
     * @param array<string, string> $headers
     * @param array<string, int|string> $rateLimit
     */
    public function __construct(
        string $message,
        int $status,
        string $errorCode,
        ?array $details = null,
        string $body = '',
        array $headers = [],
        public readonly ?string $reason = null,
        public readonly ?int $retryAfter = null,
        public readonly ?string $resetAt = null,
        public readonly ?int $limit = null,
        public readonly ?int $usage = null,
        public readonly ?int $remaining = null,
        public readonly ?int $needed = null,
        public readonly ?string $plan = null,
        public readonly ?string $upgradeUrl = null,
        public readonly array $rateLimit = [],
    ) {
        parent::__construct($message, $status, $errorCode, $details, $body, $headers);
    }
}
