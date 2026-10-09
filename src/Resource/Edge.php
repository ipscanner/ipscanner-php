<?php

declare(strict_types=1);

namespace IPScanner\Resource;

final class Edge extends Resource
{
    /**
     * Combined Agentscan and network verdict for one request, with the site's policy when $site is given. Metered as 2 requests.
     *
     * @param array<string, string>|null $headers
     * @param array<string, bool>|null $headlessFlags
     * @return array<mixed>
     */
    public function check(
        string $ip,
        ?string $site = null,
        ?string $userAgent = null,
        ?string $ja4 = null,
        ?array $headers = null,
        ?array $headlessFlags = null,
        ?string $requestId = null,
    ): array {
        return $this->client->request('POST', '/v1/edge/check', body: self::compact([
            'site' => $site,
            'ip' => $ip,
            'user_agent' => $userAgent,
            'ja4' => $ja4,
            'headers' => self::map($headers),
            'headless_flags' => self::map($headlessFlags),
            'request_id' => $requestId,
        ]));
    }
}
