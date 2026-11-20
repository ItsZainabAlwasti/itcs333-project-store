<?php
declare(strict_types=1);

/**
 * ITCS333 Project starter — m1_auth handler (module under construction).
 * Implement the endpoints in contracts/ for your module.
 * The routing context is in $GLOBALS['__route'] ('area', 'rest', 'uri').
 * Use db() from src/db.php and the helpers in src/http.php.
 */

$rest = $GLOBALS['__route']['rest'] ?? '';

// TODO: implement your module's endpoints here (see contracts/).
if ($rest === 'register' && http_method() === 'POST') {
    $data = json_body();

    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

  if (!is_string($username) ||
    !is_string($password) ||
    trim($username) === '' ||
    $password === '') {
        send_error(422, 'VALIDATION', [
            'fields' => ['username' => 'required']
        ]);
    }
    $username = trim($username);
    if (strlen($username) > 50) {
    send_error(422, 'VALIDATION', [
        'fields' => ['username' => 'too long']
    ]);
}
    $pdo = db();

$stmt = $pdo->prepare(
    "SELECT id FROM users WHERE username = ?"
);
$stmt->execute([$username]);

if ($stmt->fetch()) {
    send_error(409, 'USERNAME_TAKEN');
}
   $passwordHash = password_hash($password, PASSWORD_DEFAULT);
   $id = db_insert_and_get_id($pdo, 'users', [
    'username' => $username,
    'password_hash' => $passwordHash,
    'is_admin' => 0
]); 
    send_json(201, [
    'id' => $id,
    'username' => $username,
    'is_admin' => 0
]);
}
if ($rest === 'login' && http_method() === 'POST') {
    $data = json_body();

    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';
    if (!is_string($username) ||
        !is_string($password) ||
        trim($username) === '' ||
        $password === '') {
        send_error(401, 'INVALID_CREDENTIALS');
    }
    $username = trim($username);

$pdo = db();

$stmt = $pdo->prepare(
    "SELECT id, username, password_hash, is_admin
     FROM users WHERE username = ?"
);

$stmt->execute([$username]);
$user = $stmt->fetch();
    if (!$user || !password_verify($password, $user['password_hash'])) {
    send_error(401, 'INVALID_CREDENTIALS');
}
    session_regenerate_id(true);

$_SESSION['user_id'] = (int) $user['id'];
$_SESSION['username'] = $user['username'];
    send_json(200, [
    'id' => (int) $user['id'],
    'username' => $user['username'],
    'is_admin' => (int) $user['is_admin'],
    'token' => 'session'
]);
}
if ($rest === 'logout' && http_method() === 'POST') {
    $_SESSION = [];
    session_destroy();

    send_json(200, ['ok' => true]);
}
if ($rest === 'me' && http_method() === 'GET') {
    if (empty($_SESSION['user_id'])) {
        send_error(401, 'AUTH_REQUIRED');
    }

    $pdo = db();

    $stmt = $pdo->prepare(
        "SELECT id, username, is_admin FROM users WHERE id = ?"
    );

    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();

    if (!$user) {
        send_error(401, 'AUTH_REQUIRED');
    }

    send_json(200, [
        'id' => (int) $user['id'],
        'username' => $user['username'],
        'is_admin' => (int) $user['is_admin']
    ]);
}
send_error(501, 'NOT_IMPLEMENTED', ['module' => 'm1_auth', 'rest' => $rest]);
