<?php
/**
 * Tests PHPUnit pour la page d'inscription
 * 
 * @author Ismail KHLIF, Islem BARGUI
 * @version 1.0
 */

use PHPUnit\Framework\TestCase;

class RegisterTest extends TestCase
{
    /**
     * Test de validation du nom d'utilisateur - Cas valides
     */
    public function testValidUsername(): void
    {
        $this->assertTrue($this->isValidUsername('john_doe'));
        $this->assertTrue($this->isValidUsername('User123'));
        $this->assertTrue($this->isValidUsername('test_user_2024'));
    }
    
    /**
     * Test de validation du nom d'utilisateur - Cas invalides
     */
    public function testInvalidUsername(): void
    {
        // Trop court
        $this->assertFalse($this->isValidUsername('ab'));
        
        // Caractères spéciaux non autorisés
        $this->assertFalse($this->isValidUsername('user@name'));
        $this->assertFalse($this->isValidUsername('user name'));
        $this->assertFalse($this->isValidUsername('user-name'));
        
        // Vide
        $this->assertFalse($this->isValidUsername(''));
    }
    
    /**
     * Test de validation de l'email - Cas valides
     */
    public function testValidEmail(): void
    {
        $this->assertTrue($this->isValidEmail('test@example.com'));
        $this->assertTrue($this->isValidEmail('user.name@domain.org'));
        $this->assertTrue($this->isValidEmail('user+tag@example.fr'));
    }
    
    /**
     * Test de validation de l'email - Cas invalides
     */
    public function testInvalidEmail(): void
    {
        $this->assertFalse($this->isValidEmail('invalid-email'));
        $this->assertFalse($this->isValidEmail('@domain.com'));
        $this->assertFalse($this->isValidEmail('user@'));
        $this->assertFalse($this->isValidEmail(''));
    }
    
    /**
     * Test de validation du mot de passe - Force minimale
     */
    public function testPasswordStrength(): void
    {
        // Mot de passe valide (8+ chars, majuscule, minuscule, chiffre)
        $errors = $this->validatePassword('Password123');
        $this->assertEmpty($errors);
        
        // Mot de passe fort
        $errors = $this->validatePassword('SecureP@ss2024!');
        $this->assertEmpty($errors);
    }
    
    /**
     * Test de mot de passe trop court
     */
    public function testPasswordTooShort(): void
    {
        $errors = $this->validatePassword('Pass1');
        $this->assertContains("Le mot de passe doit contenir au moins 8 caractères.", $errors);
    }
    
    /**
     * Test de mot de passe sans majuscule
     */
    public function testPasswordNoUppercase(): void
    {
        $errors = $this->validatePassword('password123');
        $this->assertContains("Le mot de passe doit contenir au moins une majuscule.", $errors);
    }
    
    /**
     * Test de mot de passe sans minuscule
     */
    public function testPasswordNoLowercase(): void
    {
        $errors = $this->validatePassword('PASSWORD123');
        $this->assertContains("Le mot de passe doit contenir au moins une minuscule.", $errors);
    }
    
    /**
     * Test de mot de passe sans chiffre
     */
    public function testPasswordNoDigit(): void
    {
        $errors = $this->validatePassword('PasswordOnly');
        $this->assertContains("Le mot de passe doit contenir au moins un chiffre.", $errors);
    }
    
    /**
     * Test de correspondance des mots de passe
     */
    public function testPasswordsMatch(): void
    {
        $this->assertTrue($this->passwordsMatch('Password123', 'Password123'));
        $this->assertFalse($this->passwordsMatch('Password123', 'Password124'));
        $this->assertFalse($this->passwordsMatch('Password123', 'password123'));
    }
    
    /**
     * Test du hachage du mot de passe
     */
    public function testPasswordHashing(): void
    {
        $password = 'SecurePassword123';
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        
        // Le hash ne doit pas être le mot de passe en clair
        $this->assertNotEquals($password, $hash);
        
        // Le hash doit être vérifiable
        $this->assertTrue(password_verify($password, $hash));
        
        // Un mauvais mot de passe ne doit pas être vérifié
        $this->assertFalse(password_verify('WrongPassword', $hash));
    }
    
    /**
     * Test de génération de token CSRF
     */
    public function testCsrfTokenGeneration(): void
    {
        $token = bin2hex(random_bytes(32));
        
        // Le token doit faire 64 caractères (32 bytes en hex)
        $this->assertEquals(64, strlen($token));
        
        // Le token doit être hexadécimal
        $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $token);
    }
    
    /**
     * Test de validation du token CSRF
     */
    public function testCsrfTokenValidation(): void
    {
        $token = bin2hex(random_bytes(32));
        
        // Token identique doit être valide
        $this->assertTrue(hash_equals($token, $token));
        
        // Token différent doit être invalide
        $differentToken = bin2hex(random_bytes(32));
        $this->assertFalse(hash_equals($token, $differentToken));
    }
    
    /**
     * Test de l'échappement HTML
     */
    public function testHtmlEscaping(): void
    {
        $malicious = '<script>alert("XSS")</script>';
        $escaped = htmlspecialchars($malicious, ENT_QUOTES, 'UTF-8');
        
        $this->assertStringNotContainsString('<script>', $escaped);
        $this->assertStringNotContainsString('</script>', $escaped);
    }
    
    /**
     * Test de protection contre l'injection SQL
     * (Simule la préparation d'une requête)
     */
    
    private function isValidUsername(string $username): bool
    {
        if (empty($username)) return false;
        if (strlen($username) < 3 || strlen($username) > 50) return false;
        return preg_match('/^[a-zA-Z0-9_]+$/', $username) === 1;
    }
    
    private function isValidEmail(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
    
    private function validatePassword(string $password): array
    {
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
    
    private function passwordsMatch(string $password, string $confirm): bool
    {
        return $password === $confirm;
    }
    
    private function sanitizeForSql(string $input): string
    {
        // Simulation de sanitization (en réalité, utiliser PDO::prepare)
        return addslashes($input);
    }

    public function testSqlInjectionPrevention(): void
{
    $maliciousInput = "'; DROP TABLE users; --";
    $sanitized = $this->sanitizeForSql($maliciousInput);

    // L'entrée doit être modifiée (échappée)
    $this->assertNotEquals($maliciousInput, $sanitized);
}

}
