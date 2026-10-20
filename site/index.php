<?php
// Start a PHP session. This makes PHP send a "PHPSESSID" cookie.
// Whether that cookie gets the HttpOnly / Secure / SameSite flags is
// decided by php.ini, which is different in Target B and Target C.
session_start();

// Count visits so the session actually has something in it.
$_SESSION['visits'] = ($_SESSION['visits'] ?? 0) + 1;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WEB404 Sample Site</title>
</head>
<body>
    <h1>WEB404 Sample Site</h1>
    <p>This is a small sample website used for a Nikto vulnerability assessment.</p>
    <p>You have visited this page <?php echo (int) $_SESSION['visits']; ?> time(s) in this session.</p>
    <p><a href="/files/">Browse shared files</a></p>
</body>
</html>
