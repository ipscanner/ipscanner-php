<?php

declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path === '/echo') {
    header('Content-Type: application/json');
    header('X-RateLimit-Limit: 1000');
    echo json_encode([
        'method' => $_SERVER['REQUEST_METHOD'],
        'auth' => $_SERVER['HTTP_AUTHORIZATION'] ?? null,
        'body' => file_get_contents('php://input'),
    ]);
    return;
}

if ($path === '/stream') {
    header('Content-Type: application/x-ndjson');
    $lines = [
        '{"type":"meta","total":2}',
        '{"type":"result","ip":"1.2.3.4"}',
        '{"type":"result","index":1,"ip":"5.6.7.8"}',
        '{"type":"done","reason":"complete","processed":2,"total":2}',
    ];
    foreach ($lines as $line) {
        echo $line, "\n";
        flush();
        usleep(20000);
    }
    return;
}

if ($path === '/slow') {
    sleep(2);
    echo '{}';
    return;
}

http_response_code(404);
header('Content-Type: application/json');
echo '{"error":"not_found","message":"Nothing here"}';
