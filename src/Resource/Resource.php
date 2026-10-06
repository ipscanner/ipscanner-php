<?php

declare(strict_types=1);

namespace IPScanner\Resource;

use IPScanner\Client;

abstract class Resource
{
    public function __construct(protected readonly Client $client)
    {
    }

    /**
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    protected static function compact(array $body): array
    {
        return array_filter($body, static fn ($value) => $value !== null);
    }

    /**
     * @param array<mixed>|null $map
     */
    protected static function map(?array $map): ?object
    {
        return $map === null ? null : (object) $map;
    }

    protected static function segment(string $value): string
    {
        return rawurlencode($value);
    }
}
