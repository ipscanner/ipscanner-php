<?php

declare(strict_types=1);

namespace IPScanner\Resource;

use DateTimeInterface;

final class Provenance extends Resource
{
    /**
     * Records a signed attestation for the address. The response keys are snake_case.
     *
     * @param array<string, mixed>|null $requestContext
     * @return array<mixed>
     */
    public function check(string $ip, ?string $claimedJurisdiction = null, ?array $requestContext = null): array
    {
        return $this->client->request('POST', '/v1/provenance/check', body: self::compact([
            'ip' => $ip,
            'claimed_jurisdiction' => $claimedJurisdiction,
            'request_context' => self::map($requestContext),
        ]));
    }

    /**
     * @return array<mixed>
     */
    public function verify(): array
    {
        return $this->client->request('GET', '/v1/provenance/verify');
    }

    /**
     * @return array<mixed>
     */
    public function verifyAnchored(): array
    {
        return $this->client->request('POST', '/v1/provenance/verify', body: []);
    }

    /**
     * @return array<mixed>
     */
    public function chain(?int $limit = null, ?int $before = null): array
    {
        return $this->client->request('GET', '/v1/provenance/chain', [
            'limit' => $limit,
            'before' => $before,
        ]);
    }

    /**
     * @return array<mixed>
     */
    public function jurisdictions(): array
    {
        return $this->client->request('GET', '/v1/provenance/jurisdictions');
    }

    /**
     * Returns the attestation chain as CSV. Dates are RFC3339 or YYYY-MM-DD.
     */
    public function export(DateTimeInterface|string|null $from = null, DateTimeInterface|string|null $to = null): string
    {
        return $this->client->requestRaw('GET', '/v1/provenance/export', [
            'from' => self::date($from),
            'to' => self::date($to),
        ], accept: 'text/csv');
    }

    private static function date(DateTimeInterface|string|null $value): ?string
    {
        return $value instanceof DateTimeInterface ? $value->format(DateTimeInterface::RFC3339) : $value;
    }
}
