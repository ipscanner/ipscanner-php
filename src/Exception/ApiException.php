<?php

declare(strict_types=1);

namespace IPScanner\Exception;

class ApiException extends IPScannerException
{
    /**
     * @param array<string, mixed>|null $details
     * @param array<string, string> $headers
     */
    public function __construct(
        string $message,
        public readonly int $status,
        public readonly string $errorCode,
        public readonly ?array $details = null,
        public readonly string $body = '',
        public readonly array $headers = [],
    ) {
        parent::__construct($message, $status);
    }
}
