<?php

declare(strict_types=1);

namespace IPScanner\Resource;

final class Email extends Resource
{
    /**
     * Checks one address: syntax, throwaway domains, mail servers, typos and role addresses. One request.
     *
     * @return array<mixed>
     */
    public function check(string $email): array
    {
        return $this->client->request('POST', '/v1/email/check', body: ['email' => $email]);
    }
}
