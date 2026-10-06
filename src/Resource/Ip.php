<?php

declare(strict_types=1);

namespace IPScanner\Resource;

final class Ip extends Resource
{
    /**
     * Full lookup of an IPv4, IPv6, CIDR or hostname target.
     *
     * @return array<mixed>
     */
    public function lookup(string $target): array
    {
        return $this->client->request('POST', '/v1/ip/lookup', body: ['target' => $target]);
    }

    /**
     * @return array<mixed>
     */
    public function vpn(string $ip): array
    {
        return $this->client->request('GET', '/v1/vpn/' . self::segment($ip));
    }

    /**
     * @return array<mixed>
     */
    public function proxy(string $ip): array
    {
        return $this->client->request('GET', '/v1/proxy/' . self::segment($ip));
    }

    /**
     * @return array<mixed>
     */
    public function geo(string $ip): array
    {
        return $this->client->request('GET', '/v1/geo/' . self::segment($ip));
    }

    /**
     * @return array<mixed>
     */
    public function asn(string $ip): array
    {
        return $this->client->request('GET', '/v1/asn/' . self::segment($ip));
    }

    /**
     * @return array<mixed>
     */
    public function whois(string $domain): array
    {
        return $this->client->request('GET', '/v1/whois/' . self::segment($domain));
    }

    /**
     * Lookup history for the account, newest first. Pass nextBefore from the previous page as $before.
     *
     * @return array<mixed>
     */
    public function history(?int $limit = null, ?int $before = null, ?string $verdict = null): array
    {
        return $this->client->request('GET', '/v1/ip/history', [
            'limit' => $limit,
            'before' => $before,
            'verdict' => $verdict,
        ]);
    }

    /**
     * Keyless demo lookup.
     *
     * @return array<mixed>
     */
    public function demo(string $ip): array
    {
        return $this->client->request('GET', '/v1/demo/' . self::segment($ip));
    }

    /**
     * Details for the caller's own address. Keyless.
     *
     * @return array<mixed>
     */
    public function myip(): array
    {
        return $this->client->request('GET', '/v1/myip');
    }
}
