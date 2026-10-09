<?php

declare(strict_types=1);

namespace IPScanner\Resource;

use Generator;

final class Bulk extends Resource
{
    private const EVENT_DEFAULTS = [
        'type' => '',
        'index' => 0,
        'total' => 0,
        'input' => '',
        'reason' => '',
        'message' => '',
        'error' => '',
        'ip' => '',
        'verdict' => '',
        'classification' => '',
        'confidence' => 0.0,
        'anonymized' => false,
        'vpnProvider' => '',
        'score' => 0,
        'grade' => '',
        'isTorExit' => false,
        'asn' => '',
        'asnName' => '',
        'asnType' => '',
        'country' => '',
        'processed' => 0,
        'failed' => 0,
        'metered' => 0,
        'planRequired' => '',
        'locked' => [],
    ];

    /**
     * Scores a list of addresses, or a pasted blob in $input, in one request.
     *
     * @param list<string>|null $ips
     * @return array<mixed>
     */
    public function check(?array $ips = null, ?string $input = null): array
    {
        return $this->client->request('POST', '/v1/bulk/check', body: self::compact([
            'ips' => $ips,
            'input' => $input,
        ]));
    }

    /**
     * Streams results as they are produced. Yields meta, result, error and done events.
     * Null and missing fields get empty defaults; locked fields are listed in 'locked'.
     * The done event carries 'complete' => true only when every address was processed.
     *
     * @param list<string>|null $ips
     * @return Generator<int, array<string, mixed>>
     */
    public function stream(?array $ips = null, ?string $input = null): Generator
    {
        $lines = $this->client->streamLines('/v1/ip/bulk', self::compact([
            'ips' => $ips,
            'input' => $input,
        ]));

        foreach ($lines as $line) {
            $event = array_filter($line, static fn ($value) => $value !== null) + self::EVENT_DEFAULTS;
            if ($event['type'] === 'done') {
                $event['complete'] = $event['reason'] === 'complete'
                    && $event['processed'] + $event['failed'] >= $event['total'];
            }
            yield $event;
        }
    }
}
