<?php

declare(strict_types=1);

namespace IPScanner\Resource;

final class Account extends Resource
{
    /**
     * @return array<mixed>
     */
    public function limits(): array
    {
        return $this->client->request('GET', '/v1/user/limits');
    }

    /**
     * @return array<mixed>
     */
    public function usage(): array
    {
        return $this->client->request('GET', '/v1/usage/summary');
    }
}
