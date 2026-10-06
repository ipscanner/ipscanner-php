<?php

declare(strict_types=1);

namespace IPScanner\Resource;

final class Crawlers extends Resource
{
    /**
     * @return array<mixed>
     */
    public function list(): array
    {
        return $this->client->request('GET', '/v1/crawlers');
    }
}
