<?php

declare(strict_types=1);

namespace IPScanner\Resource;

final class Sites extends Resource
{
    /**
     * The site's mode and per traffic class policy. Not metered.
     *
     * @return array<mixed>
     */
    public function policy(string $id): array
    {
        return $this->client->request('GET', '/v1/sites/' . self::segment($id) . '/policy');
    }
}
