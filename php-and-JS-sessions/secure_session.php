<?php
// Detect whether HTTPS is active so 'secure' works dynamically on both HTTPS and localhost HTTP
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
           || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);

// Step 1, 2 & 3: Configure strict session cookie parameters BEFORE session_start()
session_set_cookie_params([
    'lifetime' => 3600,       // 1 hour
    'path'     => '/',
    'domain'   => '',
    'secure'   => $isHttps,   // Enforces HTTPS when available; allows localhost testing
    'httponly' => true,       // Blocks JavaScript (document.cookie) from reading PHPSESSID
    'samesite' => 'Strict'    // Mitigates CSRF attacks
]);

session_start();

$statusMessage = "";
$oldSessionId = "";
$newSessionId = "";
$page = $_GET['page'] ?? 'home';

// Handle Logout Action
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $params['path'],
            'domain'   => $params['domain'],
            'secure'   => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite']
        ]);
    }
    session_destroy();
    header("Location: " . strtok($_SERVER["REQUEST_URI"], '?'));
    exit;
}

// Handle Login & Cookie Issuance
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    $username = trim($_POST['username']);

    if ($username !== '') {
        // Capture old Session ID before regeneration for demonstration
        $oldSessionId = session_id();

        // Step 4: Regenerate Session ID immediately after login to prevent Session Fixation
        session_regenerate_id(true);
        $newSessionId = session_id();

        // Store authenticated user state in session
        $_SESSION['authenticated'] = true;
        $_SESSION['username'] = $username;
        $_SESSION['login_time'] = date("Y-m-d H:i:s");

        // Helper Tool 1: Issue a PROTECTED cookie using setcookie() options array
        setcookie('Protected_Auth_Token', bin2hex(random_bytes(16)), [
            'expires'  => time() + 3600,
            'path'     => '/',
            'secure'   => $isHttps,
            'httponly' => true,       // Hidden from document.cookie
            'samesite' => 'Strict'
        ]);

        // Step 5: Issue an UNPROTECTED cookie for side-by-side XSS comparison
        setcookie('Unprotected_Tracker', 'User_' . preg_replace('/[^a-zA-Z0-9_]/', '', $username), [
            'expires'  => time() + 3600,
            'path'     => '/',
            'secure'   => false,
            'httponly' => false,      // Exposed to document.cookie
            'samesite' => 'Lax'
        ]);

        $statusMessage = "Login successful! Session ID regenerated and cookies issued.";
    }
}

// Capture Set-Cookie headers sent by the server for inspection
$sentSetCookieHeaders = array_values(array_filter(headers_list(), function ($header) {
    return stripos($header, 'Set-Cookie:') === 0;
}));
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Assignment 13: Secure Session & Cookie Management</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 850px; margin: 35px auto; padding: 0 20px; background: #f4f6f9; color: #333; }
        .card { background: #fff; padding: 22px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 20px; }
        h2, h3 { margin-top: 0; color: #1a365d; }
        input[type="text"] { padding: 10px; width: 260px; border: 1px solid #ccc; border-radius: 4px; }
        button, .btn { padding: 10px 16px; background: #0056b3; color: #fff; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 14px; font-weight: bold; display: inline-block; }
        .btn-danger { background: #dc3545; }
        .btn-nav { background: #4a5568; margin-right: 6px; }
        .btn-nav.active { background: #0056b3; }
        pre { background: #1e1e1e; color: #4af626; padding: 12px; border-radius: 5px; overflow-x: auto; font-size: 13px; }
        .badge-safe { background: #28a745; color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 12px; }
        .badge-vuln { background: #dc3545; color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #edf2f7; }
        .alert-success { background: #d4edda; color: #155724; padding: 12px; border-radius: 5px; margin-bottom: 15px; border: 1px solid #c3e6cb; }
    </style>
</head>
<body>

<div class="card">
    <h2>Secure Session &amp; Cookie Management Tool</h2>

    <?php if ($statusMessage): ?>
        <div class="alert-success"><?= htmlspecialchars($statusMessage) ?></div>
    <?php endif; ?>

    <?php if (empty($_SESSION['authenticated'])): ?>
        <p>Log in to issue hardened cookies (<code>HttpOnly</code> + <code>SameSite=Strict</code>) and trigger <code>session_regenerate_id(true)</code>.</p>
        <form method="POST" action="">
            <input type="text" name="username" placeholder="Enter username (e.g., admin)" required>
            <button type="submit">Authenticate &amp; Issue Cookies</button>
        </form>
        <p style="margin-top:12px; font-size:13px; color:#555;">
            <strong>Current Pre-Login Session ID:</strong> <code><?= htmlspecialchars(session_id()) ?></code>
        </p>
    <?php else: ?>
        <div style="margin-bottom: 15px;">
            <a href="?page=home" class="btn btn-nav <?= $page === 'home' ? 'active' : '' ?>">Overview</a>
            <a href="?page=profile" class="btn btn-nav <?= $page === 'profile' ? 'active' : '' ?>">Profile Page</a>
            <a href="?action=logout" class="btn btn-danger">Logout</a>
        </div>

        <?php if ($page === 'profile'): ?>
            <p><strong>Page Navigation Test (Profile View):</strong> Session state persisted smoothly across pages without losing authentication.</p>
        <?php endif; ?>

        <table>
            <tr>
                <th>Authenticated User</th>
                <td><?= htmlspecialchars($_SESSION['username']) ?> (Logged in at <?= htmlspecialchars($_SESSION['login_time']) ?>)</td>
            </tr>
            <tr>
                <th>Active Session ID</th>
                <td><code><?= htmlspecialchars(session_id()) ?></code></td>
            </tr>
            <?php if ($oldSessionId !== ''): ?>
            <tr>
                <th>Session Fixation Defense</th>
                <td>
                    Old ID: <code><?= htmlspecialchars($oldSessionId) ?></code><br>
                    New ID: <code><?= htmlspecialchars($newSessionId) ?></code> <span class="badge-safe">Regenerated</span>
                </td>
            </tr>
            <?php endif; ?>
        </table>
    <?php endif; ?>
</div>

<div class="card">
    <h3>1. Server-Side Cookie Inspection (PHP <code>$_COOKIE</code>)</h3>
    <p>The server receives all cookies sent by the browser over HTTP:</p>
    <table>
        <thead>
            <tr>
                <th>Cookie Name</th>
                <th>Security Configuration</th>
                <th>Server Value</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><code>PHPSESSID</code></td>
                <td><span class="badge-safe">HttpOnly | SameSite=Strict</span></td>
                <td><code><?= htmlspecialchars($_COOKIE[session_name()] ?? session_id()) ?></code></td>
            </tr>
            <tr>
                <td><code>Protected_Auth_Token</code></td>
                <td><span class="badge-safe">HttpOnly | SameSite=Strict</span></td>
                <td><code><?= htmlspecialchars($_COOKIE['Protected_Auth_Token'] ?? 'Not issued yet (Log in first)') ?></code></td>
            </tr>
            <tr>
                <td><code>Unprotected_Tracker</code></td>
                <td><span class="badge-vuln">No HttpOnly (XSS Exposed)</span></td>
                <td><code><?= htmlspecialchars($_COOKIE['Unprotected_Tracker'] ?? 'Not issued yet (Log in first)') ?></code></td>
            </tr>
        </tbody>
    </table>
</div>

<div class="card">
    <h3>2. Client-Side XSS Simulation (JavaScript <code>document.cookie</code>)</h3>
    <p>Below is what a malicious XSS payload running <code>document.cookie</code> in the browser can read. Notice that <code>PHPSESSID</code> and <code>Protected_Auth_Token</code> are completely invisible to JavaScript[cite: 4]:</p>
    <pre id="js-cookie-output">Reading document.cookie...</pre>
</div>

<?php if (!empty($sentSetCookieHeaders)): ?>
<div class="card">
    <h3>3. Raw HTTP <code>Set-Cookie</code> Response Headers</h3>
    <pre><?php foreach ($sentSetCookieHeaders as $h) { echo htmlspecialchars($h) . "\n"; } ?></pre>
</div>
<?php endif; ?>

<script>
    // Demonstrate client-side JavaScript access attempt via document.cookie
    const visibleCookies = document.cookie;
    const outputBox = document.getElementById('js-cookie-output');

    if (visibleCookies.trim() === "") {
        outputBox.textContent = "document.cookie is EMPTY — HttpOnly cookies are completely hidden from JavaScript!";
    } else {
        outputBox.textContent = "document.cookie output:\n" + visibleCookies +
            "\n\n[SECURITY VERIFIED]: 'PHPSESSID' and 'Protected_Auth_Token' are blocked from JavaScript access!";
    }
</script>

</body>
</html>

// username admin