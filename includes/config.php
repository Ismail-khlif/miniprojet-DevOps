<?php
$db_host = getenv('DB_HOST') ?: 'localhost';
$db_user = getenv('DB_USER') ?: 'root';
$db_pass = getenv('DB_PASS') ?: '';
$db_name = getenv('DB_NAME') ?: 'notes_esigelec';

// Définir les constantes
define('DB_HOST', $db_host);
define('DB_USER', $db_user);
define('DB_PASS', $db_pass);
define('DB_NAME', $db_name);

try {
    $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
    
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,  // Désactiver l'émulation pour plus de sécurité
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
    ];
    
    $dbh = new PDO($dsn, DB_USER, DB_PASS, $options);
    
} catch (PDOException $e) {
    // En production, ne pas afficher les détails de l'erreur
    error_log("Erreur de connexion PDO: " . $e->getMessage());
    
    if (getenv('APP_ENV') === 'production') {
        die("Erreur de connexion à la base de données. Veuillez réessayer plus tard.");
    } else {
        die("Erreur de connexion: " . $e->getMessage());
    }
}


try {
    $dbh1 = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($dbh1->connect_error) {
        throw new Exception("Connexion MySQLi échouée: " . $dbh1->connect_error);
    }
    
    // Définir le charset
    $dbh1->set_charset("utf8mb4");
    
} catch (Exception $e) {
    error_log("Erreur de connexion MySQLi: " . $e->getMessage());
    
    if (getenv('APP_ENV') === 'production') {
        die("Erreur de connexion à la base de données. Veuillez réessayer plus tard.");
    } else {
        die("Erreur MySQLi: " . $e->getMessage());
    }
}

if (session_status() === PHP_SESSION_NONE) {
    // Configuration sécurisée des sessions
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_strict_mode', 1);
    ini_set('session.use_only_cookies', 1);

}

define('APP_NAME', 'Site Notes ESIGELEC');
define('APP_VERSION', '2.0');
define('APP_ENV', getenv('APP_ENV') ?: 'development');

date_default_timezone_set('Europe/Paris');
?>
