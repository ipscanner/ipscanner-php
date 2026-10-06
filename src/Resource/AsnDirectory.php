<?php

declare(strict_types=1);

namespace IPScanner\Resource;

use InvalidArgumentException;

final class AsnDirectory extends Resource
{
    /**
     * Largest networks, ranked by 'addresses' or 'prefixes'.
     *
     * @return array<mixed>
     */
    public function top(?int $top = null, ?string $by = null): array
    {
        return $this->client->request('GET', '/v1/asn/directory', ['top' => $top, 'by' => $by]);
    }

    /**
     * @return array<mixed>
     */
    public function search(string $q, ?int $limit = null): array
    {
        return $this->client->request('GET', '/v1/asn/directory', ['q' => $q, 'limit' => $limit]);
    }

    /**
     * Accepts 15169 or "AS15169".
     *
     * @return array<mixed>
     */
    public function get(int|string $asn): array
    {
        $number = is_int($asn) ? (string) $asn : preg_replace('/^as/i', '', trim($asn));
        if ($number === null || !ctype_digit($number)) {
            throw new InvalidArgumentException('ASN must look like 15169 or AS15169');
        }

        return $this->client->request('GET', '/v1/asn/directory/' . $number);
    }
}
