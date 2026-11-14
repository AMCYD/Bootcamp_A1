<?php
// Helper Tool 1 & 2: Initialize in-memory SQLite database via PDO with Exception Error Mode
try {
    $pdo = new PDO('sqlite::memory:', null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);

    // Step 2: Programmatically create the users table and insert sample records
    $pdo->exec("
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        );
    ");

    $pdo->exec("
        INSERT INTO users (username, email, role) VALUES
        ('admin', 'admin@security-lab.local', 'Administrator'),
        ('ahmed', 'ahmed@security-lab.local', 'SOC Analyst'),
        ('sara', 'sara@security-lab.local', 'Incident Responder');
    ");
} catch (PDOException $e) {
    die("Database initialization failed.");
}

// Capture user input and selected execution mode from GET parameters
$usernameInput = $_GET['username'] ?? '';
$mode = $_GET['mode'] ?? 'secure'; // Defaults to 'secure'
$results = [];
$executedQueryDisplay = "";
$errorMessage = "";

if ($usernameInput !== '') {
    try {
        if ($mode === 'vulnerable') {
            // =================================================================
            // Step 3: INSECURE METHOD (Direct String Concatenation - Vulnerable)
            // =================================================================
            $sql = "SELECT id, username, email, role FROM users WHERE username = '" . $usernameInput . "'";
            $executedQueryDisplay = $sql;
            
            $stmt = $pdo->query($sql);
            $results = $stmt->fetchAll();

        } else {
            // =================================================================
            // Step 4: SECURE METHOD (PDO Prepared Statements)
            // =================================================================
            $sql = "SELECT id, username, email, role FROM users WHERE username = :username";
            $executedQueryDisplay = "SELECT id, username, email, role FROM users WHERE username = :username  [Bound Parameter => " . $usernameInput . "]";

            $stmt = $pdo->prepare($sql);
            $stmt->execute([':username' => $usernameInput]);
            $results = $stmt->fetchAll();
        }
    } catch (PDOException $e) {
        // Safely catch errors without leaking database schema information
        if ($mode === 'vulnerable') {
            $errorMessage = "SQL Error (Leaked in Vulnerable Mode): " . $e->getMessage();
        } else {
            $errorMessage = "An unexpected error occurred while processing your request.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Assignment 11: SQLi Defense Lab (PDO vs Concatenation)</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #f4f6f9; color: #333; }
        .card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        input[type="text"], select { padding: 10px; width: 60%; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 10px 18px; border: none; border-radius: 4px; background: #0056b3; color: #fff; cursor: pointer; font-weight: bold; }
        .badge-vuln { background: #dc3545; color: #fff; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .badge-sec { background: #28a745; color: #fff; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        pre { background: #222; color: #0f0; padding: 12px; border-radius: 4px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #0056b3; color: #fff; }
        .alert { padding: 12px; background: #f8d7da; color: #721c24; border-radius: 4px; margin-top: 10px; }
    </style>
</head>
<body>

<div class="card">
    <h2>SQL Injection Defense Comparison Lab</h2>
    <p>Test payload tip: Try entering <code>' OR '1'='1</code> in both modes to observe how PDO Prepared Statements neutralize SQL Injection.</p>
    
    <form method="GET" action="">
        <label><strong>Username Lookup:</strong></label><br><br>
        <input type="text" name="username" placeholder="Enter username (e.g., admin or ' OR '1'='1)" value="<?= htmlspecialchars($usernameInput) ?>" required>
        <select name="mode" style="width: 22%;">
            <option value="secure" <?= $mode === 'secure' ? 'selected' : '' ?>>Secure (PDO)</option>
            <option value="vulnerable" <?= $mode === 'vulnerable' ? 'selected' : '' ?>>Vulnerable</option>
        </select>
        <button type="submit">Search</button>
    </form>
</div>

<?php if ($usernameInput !== ''): ?>
<div class="card">
    <h3>
        Execution Mode: 
        <?php if ($mode === 'vulnerable'): ?>
            <span class="badge-vuln">VULNERABLE (String Concatenation)</span>
        <?php else: ?>
            <span class="badge-sec">SECURE (PDO Prepared Statement)</span>
        <?php endif; ?>
    </h3>

    <p><strong>Executed SQL Statement:</strong></p>
    <pre><?= htmlspecialchars($executedQueryDisplay) ?></pre>

    <?php if ($errorMessage): ?>
        <div class="alert"><?= htmlspecialchars($errorMessage) ?></div>
    <?php elseif (count($results) > 0): ?>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($results as $row): ?>
                    <tr>
                        <td><?= htmlspecialchars((string)$row['id']) ?></td>
                        <td><?= htmlspecialchars($row['username']) ?></td>
                        <td><?= htmlspecialchars($row['email']) ?></td>
                        <td><?= htmlspecialchars($row['role']) ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else: ?>
        <p><strong>Result:</strong> No matching user found (SQL Injection payload treated strictly as literal text).</p>
    <?php endif; ?>
</div>
<?php endif; ?>

</body>
</html>


// php -S localhost:8000