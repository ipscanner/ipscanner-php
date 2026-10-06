# IPScanner PHP SDK

[![CI](https://github.com/ipscanner/ipscanner-php/actions/workflows/ci.yml/badge.svg)](https://github.com/ipscanner/ipscanner-php/actions/workflows/ci.yml)

Official PHP client for the [IPScanner](https://ipscanner.io) API.

Full API reference: https://ipscanner.io/api-documentation

## Install

```bash
composer require ipscanner.io/sdk
```

Requires PHP 8.1 or newer with the curl and json extensions.

## Quick start

```php
use IPScanner\Client;

$client = new Client(apiKey: 'pk_live_...');

$result = $client->ip->lookup('8.8.8.8');

echo $result['verdict']['classification'];
echo $result['purity']['grade'];
```

Every method returns the decoded JSON response as an associative array, using the same key names as the API.

## Usage

### IP

```php
$client->ip->lookup('example.com');          // IPv4, IPv6, CIDR or hostname
$client->ip->vpn('1.2.3.4');
$client->ip->proxy('1.2.3.4');
$client->ip->geo('2001:db8::1');
$client->ip->asn('1.2.3.4');
$client->ip->whois('example.com');
$client->ip->history(limit: 50, verdict: 'vpn');
$client->ip->demo('1.2.3.4');                // no key needed
$client->ip->myip();                         // no key needed
```

Page through history by passing the previous `nextBefore` as `before`. A `nextBefore` of 0 means there are no more pages.

### Bulk

```php
$report = $client->bulk->check(ips: ['1.2.3.4', '5.6.7.8']);
$report = $client->bulk->check(input: file_get_contents('ips.txt'));
```

`stream()` returns a generator of events as the server produces them: one `meta`, then `result` and `error` events, then one `done`. Missing fields are filled with empty defaults.

```php
foreach ($client->bulk->stream(ips: $ips) as $event) {
    if ($event['type'] === 'result') {
        printf("%s %s %d\n", $event['ip'], $event['verdict'], $event['score']);
    } elseif ($event['type'] === 'done' && !$event['complete']) {
        printf("Stopped early: %s\n", $event['reason']);
    }
}
```

`complete` on the `done` event is true only when the reason is `complete` and every address was processed. The request is sent when iteration starts.

### Agentscan

```php
$client->agentscan->check(
    ip: '1.2.3.4',
    userAgent: $_SERVER['HTTP_USER_AGENT'] ?? null,
    headers: ['accept-language' => 'en-GB'],
);

$client->agentscan->verify(ip: '66.249.66.1', bot: 'googlebot');
$client->agentscan->batch([
    ['ip' => '1.2.3.4', 'userAgent' => 'curl/8.0'],
]);
$client->agentscan->allowlist();
$client->agentscan->selfCheck();
```

### Provenance

```php
$attestation = $client->provenance->check(ip: '1.2.3.4', claimedJurisdiction: 'GB');
echo $attestation['policy_action'];

$client->provenance->verify();
$client->provenance->verifyAnchored();
$client->provenance->chain(limit: 100);
$client->provenance->jurisdictions();
$csv = $client->provenance->export(from: '2026-01-01', to: '2026-01-31');
```

The `check` response uses snake_case keys, as the API returns them. `export` returns the CSV as a string.

### Account

```php
$client->account->limits();
$client->account->usage();
```

### ASN directory

```php
$client->asnDirectory->top(top: 20, by: 'addresses');
$client->asnDirectory->search('cloudflare', limit: 5);
$client->asnDirectory->get('AS15169');
```

### Crawlers

```php
$client->crawlers->list();
```

## Errors

All exceptions extend `IPScanner\Exception\IPScannerException`.

| Exception | When |
| --- | --- |
| `ApiException` | Any non-2xx response. Has `status`, `errorCode`, `details`, `body` and `headers`. |
| `AuthenticationException` | 401 or 403 |
| `NotFoundException` | 404 |
| `RateLimitException` | 429. Adds `reason`, `retryAfter`, `resetAt`, `limit`, `usage`, `remaining`, `needed`, `plan`, `upgradeUrl` and `rateLimit` (parsed rate limit headers). |
| `ConnectionException` | The request could not be completed. |
| `TimeoutException` | The request timed out. Extends `ConnectionException`. |

```php
use IPScanner\Exception\RateLimitException;

try {
    $client->ip->lookup('1.2.3.4');
} catch (RateLimitException $e) {
    sleep($e->retryAfter ?? 60);
}
```

GET requests are retried up to `maxRetries` times on connection errors and 502, 503 and 504 responses. POST requests and 429 responses are never retried.

## Configuration

```php
$client = new Client(
    apiKey: 'pk_live_...',              // default: IPSCANNER_API_KEY
    baseUrl: 'https://ipscanner.io',    // default: IPSCANNER_API_URL, then https://ipscanner.io
    timeout: 30,                        // seconds; bulk streams use 300
    maxRetries: 2,
    transport: null,                    // any IPScanner\Http\Transport
);
```

Keyless endpoints (`ip->demo`, `ip->myip`, `asnDirectory`, `crawlers`) work without a key.

## Licence

MIT
