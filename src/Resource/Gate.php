<?php

declare(strict_types=1);

namespace IPScanner\Resource;

final class Gate extends Resource
{
    /**
     * Redeems a gate token with the site secret. Sent without the API key and never retried. Response keys are snake_case.
     * $email (optional) adds an email check, one request.
     *
     * @return array<mixed>
     */
    public function verify(string $secret, string $token, ?string $remoteIp = null, ?string $email = null): array
    {
        return $this->client->request('POST', '/v1/gate/verify', body: self::compact([
            'secret' => $secret,
            'token' => $token,
            'remote_ip' => $remoteIp,
            'email' => $email,
        ]), authenticated: false);
    }
}
