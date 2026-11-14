<?php
// Configuration Constants
$uploadDir = __DIR__ . '/uploads/';
$maxFileSize = 2 * 1024 * 1024; // 2 MB Maximum allowed size
$allowedExtensions = ['jpg', 'png']; // Step 2: Strict Extension Whitelist
$allowedMimeTypes = [
    'jpg' => 'image/jpeg',
    'png' => 'image/png'
];

$feedbackMessage = "";
$feedbackType = "";

// Ensure the dedicated uploads directory exists and disable script execution inside it
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
    file_put_contents($uploadDir . '.htaccess', "php_flag engine off\nOptions -ExecCGI\n");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Step 1: Receive the uploaded file via $_FILES['uploaded_file']
    if (!isset($_FILES['uploaded_file']) || $_FILES['uploaded_file']['error'] !== UPLOAD_ERR_OK) {
        $feedbackType = "error";
        $feedbackMessage = "Upload failed or no file was selected.";
    } else {
        $fileTmpPath = $_FILES['uploaded_file']['tmp_name'];
        $originalName = basename($_FILES['uploaded_file']['name']);
        $fileSize = $_FILES['uploaded_file']['size'];

        // Layer 1: Check Maximum File Size
        if ($fileSize <= 0 || $fileSize > $maxFileSize) {
            $feedbackType = "error";
            $feedbackMessage = "Security Alert: File size exceeds the 2MB limit or file is empty.";
        } else {
            // Layer 2: Extract extension using pathinfo() and check against strict Whitelist
            $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

            if (!in_array($extension, $allowedExtensions, true)) {
                $feedbackType = "error";
                $feedbackMessage = "Security Alert: Extension '.$extension' is not permitted. Only JPG and PNG are allowed.";
            } else {
                // Layer 3: Inspect actual internal file content (MIME Type) using Fileinfo
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $detectedMime = finfo_file($finfo, $fileTmpPath);
                finfo_close($finfo);

                if ($detectedMime !== $allowedMimeTypes[$extension]) {
                    $feedbackType = "error";
                    $feedbackMessage = "Security Alert (Spoofing Detected): Actual file content ($detectedMime) does not match '.$extension'!";
                } else {
                    // Step 4: Generate cryptographically secure random filename
                    $secureFilename = bin2hex(random_bytes(16)) . '.' . $extension;
                    $destinationPath = $uploadDir . $secureFilename;

                    // Step 5: Move file securely and restrict permissions
                    if (move_uploaded_file($fileTmpPath, $destinationPath)) {
                        chmod($destinationPath, 0644); // Read/write for owner, read-only for others (non-executable)
                        $feedbackType = "success";
                        $feedbackMessage = "File verified and uploaded safely! Saved as: " . $secureFilename;
                    } else {
                        $feedbackType = "error";
                        $feedbackMessage = "Server Error: Failed to move uploaded file to destination.";
                    }
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Assignment 12: Secure File Upload (Defense-in-Depth)</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 650px; margin: 50px auto; padding: 0 20px; background: #f4f6f9; color: #333; }
        .card { background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        input[type="file"] { margin: 15px 0; display: block; }
        button { padding: 10px 20px; background: #0056b3; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .msg { padding: 14px; border-radius: 4px; margin-top: 20px; font-weight: bold; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>

<div class="card">
    <h2>Secure File Upload System (Defense-in-Depth)</h2>
    <p>Allowed formats: <strong>JPG, PNG</strong> | Max Size: <strong>2 MB</strong></p>

    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="uploaded_file" required>
        <button type="submit">Upload & Verify</button>
    </form>

    <?php if ($feedbackMessage !== ""): ?>
        <div class="msg <?= htmlspecialchars($feedbackType) ?>">
            <?= htmlspecialchars($feedbackMessage) ?>
        </div>
    <?php endif; ?>
</div>

</body>
</html>