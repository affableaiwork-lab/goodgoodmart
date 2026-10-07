<?php
/**
 * Ethical Pantry — contact form handler
 * goodgoodmart.com
 *
 * Static site + one PHP endpoint. SiteGround runs PHP on all plans, so this
 * needs no extra service. Delivery uses PHP mail(); if you later move to SMTP
 * or an external form service, only the send_message() function changes.
 *
 * Spam protection, in order of cheapness:
 *   1. honeypot field ("website") — must be empty
 *   2. submission timing — a human takes more than 3 seconds
 *   3. field validation and length caps
 *   4. link-count heuristic on the message body
 *   5. simple per-IP rate limit via a temp file
 */

declare(strict_types=1);

const RECIPIENT     = 'hello@goodgoodmart.com';
const SITE_HOST     = 'goodgoodmart.com';
const MIN_SECONDS   = 3;
const MAX_LINKS     = 2;
const RATE_LIMIT_N  = 5;      // max submissions
const RATE_LIMIT_S  = 3600;   // per hour, per IP

// ---------------------------------------------------------------------------

function redirect(string $path): never {
    header('Location: https://' . SITE_HOST . $path, true, 303);
    exit;
}

function reject(string $lang): never {
    // Deliberately identical to success from the sender's point of view:
    // a bot learns nothing about which check caught it.
    redirect($lang === 'en' ? '/en/contact/thanks/' : '/contact/thanks/');
}

function client_ip(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

function rate_limited(string $ip): bool {
    $file = sys_get_temp_dir() . '/ep_rate_' . sha1($ip) . '.txt';
    $now  = time();
    $hits = [];
    if (is_readable($file)) {
        $raw  = (string) file_get_contents($file);
        $hits = array_filter(
            array_map('intval', explode(',', $raw)),
            static fn(int $t): bool => $t > $now - RATE_LIMIT_S
        );
    }
    if (count($hits) >= RATE_LIMIT_N) {
        return true;
    }
    $hits[] = $now;
    @file_put_contents($file, implode(',', $hits), LOCK_EX);
    return false;
}

function send_message(string $name, string $email, string $message, string $lang): bool {
    $subject = '[Ethical Pantry] Contact form — ' . mb_substr($name, 0, 60);

    $body = "New message from the goodgoodmart.com contact form.\n\n"
          . "Name:     {$name}\n"
          . "Email:    {$email}\n"
          . "Language: {$lang}\n"
          . "IP:       " . client_ip() . "\n"
          . "Time:     " . gmdate('Y-m-d H:i:s') . " UTC\n"
          . "\n----------------------------------------\n\n"
          . $message . "\n";

    $headers = [
        'From'                      => 'Ethical Pantry <no-reply@' . SITE_HOST . '>',
        'Reply-To'                  => $email,
        'Content-Type'              => 'text/plain; charset=UTF-8',
        'Content-Transfer-Encoding' => '8bit',
        'X-Mailer'                  => 'PHP/' . PHP_VERSION,
    ];

    $header_lines = [];
    foreach ($headers as $k => $v) {
        // Strip any CR/LF that could be used for header injection.
        $header_lines[] = $k . ': ' . str_replace(["\r", "\n"], '', $v);
    }

    return @mail(
        RECIPIENT,
        '=?UTF-8?B?' . base64_encode($subject) . '?=',
        $body,
        implode("\r\n", $header_lines)
    );
}

// ---------------------------------------------------------------------------

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    redirect('/contact/');
}

$lang = ($_POST['lang'] ?? 'ja') === 'en' ? 'en' : 'ja';

// 1. honeypot
if (trim((string) ($_POST['website'] ?? '')) !== '') {
    reject($lang);
}

// 2. timing — the form stamps Date.now() in milliseconds on load
$stamp = (int) ($_POST['t'] ?? 0);
if ($stamp > 0) {
    $elapsed = (time() * 1000 - $stamp) / 1000;
    if ($elapsed < MIN_SECONDS || $elapsed > 86400) {
        reject($lang);
    }
}

// 3. validation
$name    = trim((string) ($_POST['name'] ?? ''));
$email   = trim((string) ($_POST['email'] ?? ''));
$message = trim((string) ($_POST['message'] ?? ''));

if ($name === '' || $email === '' || $message === '') {
    redirect($lang === 'en' ? '/en/contact/' : '/contact/');
}
if (mb_strlen($name) > 120 || mb_strlen($email) > 200 || mb_strlen($message) > 4000) {
    reject($lang);
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    redirect($lang === 'en' ? '/en/contact/' : '/contact/');
}
// Header-injection guard on the values that reach the mail headers.
if (preg_match('/[\r\n]/', $name . $email)) {
    reject($lang);
}

// 4. link-count heuristic
if (preg_match_all('~https?://~i', $message) > MAX_LINKS) {
    reject($lang);
}

// 5. rate limit
if (rate_limited(client_ip())) {
    reject($lang);
}

send_message($name, $email, $message, $lang);

redirect($lang === 'en' ? '/en/contact/thanks/' : '/contact/thanks/');
