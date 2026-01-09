<?php
/**
 * Security Headers - À inclure dans toutes les pages
 * 
 * Ce fichier configure les en-têtes de sécurité HTTP pour protéger
 * contre les attaques courantes (XSS, Clickjacking, MIME sniffing, etc.)
 * 
 * @author Ismail KHLIF, Islem BARGUI
 * @version 1.0
 */

// Protection contre le Clickjacking
header('X-Frame-Options: DENY');

// Protection contre le MIME sniffing
header('X-Content-Type-Options: nosniff');

// Protection XSS pour les anciens navigateurs
header('X-XSS-Protection: 1; mode=block');

// Content Security Policy
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdnjs.cloudflare.com;");

// Referrer Policy
header('Referrer-Policy: strict-origin-when-cross-origin');

// Permissions Policy (anciennement Feature-Policy)
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// Masquer la version PHP
header_remove('X-Powered-By');

// Configuration des cookies de session sécurisés
if (session_status() === PHP_SESSION_ACTIVE) {
    // Paramètres de cookie sécurisés
    $cookieParams = [
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => isset($_SERVER['HTTPS']), // true si HTTPS
        'httponly' => true,
        'samesite' => 'Strict'
    ];
    
    session_set_cookie_params($cookieParams);
}

// Configuration PHP pour la sécurité
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
ini_set('session.use_only_cookies', 1);

/**
 * Fonction pour générer un token CSRF
 * 
 * @return string Token CSRF
 */
function generateCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Fonction pour valider un token CSRF
 * 
 * @param string $token Token à valider
 * @return bool True si valide, False sinon
 */
function validateCsrfToken(string $token): bool {
    if (empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Fonction pour régénérer le token CSRF
 * 
 * @return string Nouveau token CSRF
 */
function regenerateCsrfToken(): string {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf_token'];
}

/**
 * Fonction pour échapper les sorties HTML
 * 
 * @param string $string Chaîne à échapper
 * @return string Chaîne échappée
 */
function escapeHtml(string $string): string {
    return htmlspecialchars($string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/**
 * Fonction pour valider un email
 * 
 * @param string $email Email à valider
 * @return bool True si valide, False sinon
 */
function isValidEmail(string $email): bool {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Fonction pour valider la force du mot de passe
 * 
 * @param string $password Mot de passe à valider
 * @return array Liste des erreurs (vide si valide)
 */
function validatePassword(string $password): array {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = "Le mot de passe doit contenir au moins 8 caractères.";
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Le mot de passe doit contenir au moins une majuscule.";
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Le mot de passe doit contenir au moins une minuscule.";
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Le mot de passe doit contenir au moins un chiffre.";
    }
    
    return $errors;
}
?>
