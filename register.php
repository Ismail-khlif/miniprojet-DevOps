<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 0);
include 'includes/config.php';
include 'includes/security-headers.php';

// Générer un token CSRF si non existant
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Vérification du token CSRF
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = "Erreur de sécurité : token CSRF invalide.";
    } else {
        // Récupération et nettoyage des données
        $username = trim(filter_input(INPUT_POST, 'username', FILTER_SANITIZE_SPECIAL_CHARS));
        $email = trim(filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL));
        $password = $_POST['password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        
        // Validation du nom d'utilisateur
        if (empty($username)) {
            $errors[] = "Le nom d'utilisateur est requis.";
        } elseif (strlen($username) < 3 || strlen($username) > 50) {
            $errors[] = "Le nom d'utilisateur doit contenir entre 3 et 50 caractères.";
        } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            $errors[] = "Le nom d'utilisateur ne peut contenir que des lettres, chiffres et underscores.";
        }
        
        // Validation de l'email
        if (empty($email)) {
            $errors[] = "L'adresse email est requise.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "L'adresse email n'est pas valide.";
        }
        
        // Validation du mot de passe
        if (empty($password)) {
            $errors[] = "Le mot de passe est requis.";
        } elseif (strlen($password) < 8) {
            $errors[] = "Le mot de passe doit contenir au moins 8 caractères.";
        } elseif (!preg_match('/[A-Z]/', $password)) {
            $errors[] = "Le mot de passe doit contenir au moins une majuscule.";
        } elseif (!preg_match('/[a-z]/', $password)) {
            $errors[] = "Le mot de passe doit contenir au moins une minuscule.";
        } elseif (!preg_match('/[0-9]/', $password)) {
            $errors[] = "Le mot de passe doit contenir au moins un chiffre.";
        }
        
        // Vérification de la confirmation du mot de passe
        if ($password !== $confirm_password) {
            $errors[] = "Les mots de passe ne correspondent pas.";
        }
        
        // Si aucune erreur de validation, vérifier l'unicité
        if (empty($errors)) {
            try {
                // Vérifier si le nom d'utilisateur existe déjà
                $stmt = $dbh->prepare("SELECT COUNT(*) FROM users WHERE UserName = :username");
                $stmt->bindParam(':username', $username, PDO::PARAM_STR);
                $stmt->execute();
                if ($stmt->fetchColumn() > 0) {
                    $errors[] = "Ce nom d'utilisateur est déjà utilisé.";
                }
                
                // Vérifier si l'email existe déjà
                $stmt = $dbh->prepare("SELECT COUNT(*) FROM users WHERE Email = :email");
                $stmt->bindParam(':email', $email, PDO::PARAM_STR);
                $stmt->execute();
                if ($stmt->fetchColumn() > 0) {
                    $errors[] = "Cette adresse email est déjà utilisée.";
                }
                
            } catch (PDOException $e) {
                error_log("Erreur BDD lors de la vérification: " . $e->getMessage());
                $errors[] = "Une erreur est survenue. Veuillez réessayer.";
            }
        }
        
        // Si toujours aucune erreur, créer le compte
        if (empty($errors)) {
            try {
                // Hachage sécurisé du mot de passe avec PASSWORD_BCRYPT
                $hashed_password = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
                
                // Insertion avec requête préparée
                $stmt = $dbh->prepare("INSERT INTO users (UserName, Email, Password, is_admin, created_at) VALUES (:username, :email, :password, 0, NOW())");
                $stmt->bindParam(':username', $username, PDO::PARAM_STR);
                $stmt->bindParam(':email', $email, PDO::PARAM_STR);
                $stmt->bindParam(':password', $hashed_password, PDO::PARAM_STR);
                $stmt->execute();
                
                $success = true;
                
                // Régénérer le token CSRF après une action réussie
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                
                // Log de l'inscription
                error_log("Nouvel utilisateur inscrit: " . $username);
                
            } catch (PDOException $e) {
                error_log("Erreur BDD lors de l'inscription: " . $e->getMessage());
                $errors[] = "Une erreur est survenue lors de l'inscription. Veuillez réessayer.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Inscription - Site Notes ESIGELEC</title>
    <link rel="icon" type="image/x-icon" href="assets/images/favicon.png">
    <link rel="stylesheet" href="assets/css/bootstrap.min.css" media="screen">
    <link rel="stylesheet" href="assets/css/font-awesome.min.css" media="screen">
    <link rel="stylesheet" href="assets/css/main.css" media="screen">
    <style>
        .register-box {
            background: #172541;
            border-radius: 10px;
            padding: 30px;
            margin-top: 50px;
        }
        .register-box h3 {
            color: white;
            margin-bottom: 25px;
        }
        .form-control {
            margin-bottom: 15px;
        }
        .register-btn {
            background: #4CAF50;
            color: white;
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
        }
        .register-btn:hover {
            background: #45a049;
        }
        .alert {
            margin-bottom: 15px;
        }
        .password-requirements {
            font-size: 12px;
            color: #888;
            margin-top: -10px;
            margin-bottom: 15px;
        }
        .password-strength {
            height: 5px;
            margin-top: -10px;
            margin-bottom: 15px;
            border-radius: 3px;
        }
        .strength-weak { background: #dc3545; width: 25%; }
        .strength-fair { background: #ffc107; width: 50%; }
        .strength-good { background: #17a2b8; width: 75%; }
        .strength-strong { background: #28a745; width: 100%; }
    </style>
</head>
<body style="background-image: url(assets/images/back2.jpg); background-size: cover; background-position: center;">
    <div class="main-wrapper">
        <div class="container">
            <div class="row">
                <div class="col-md-6 col-md-offset-3">
                    <div class="register-box">
                        <div class="text-center">
                            <img src="assets/images/footer-logo.png" alt="Logo" style="height: 70px; margin-bottom: 20px;">
                            <h3><strong>Créer un compte</strong></h3>
                        </div>
                        
                        <?php if ($success): ?>
                            <div class="alert alert-success">
                                <strong>Félicitations !</strong> Votre compte a été créé avec succès.
                                <br><a href="admin-login.php" class="text-white"><strong>Cliquez ici pour vous connecter</strong></a>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (!empty($errors)): ?>
                            <div class="alert alert-danger">
                                <strong>Erreur(s) :</strong>
                                <ul style="margin-bottom: 0; padding-left: 20px;">
                                    <?php foreach ($errors as $error): ?>
                                        <li><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (!$success): ?>
                        <form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>" id="registerForm">
                            <!-- Token CSRF caché -->
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                            
                            <div class="form-group">
                                <label for="username" class="control-label text-white">Nom d'utilisateur</label>
                                <input type="text" 
                                       name="username" 
                                       class="form-control" 
                                       id="username" 
                                       placeholder="Entrez votre nom d'utilisateur"
                                       value="<?php echo isset($username) ? htmlspecialchars($username, ENT_QUOTES, 'UTF-8') : ''; ?>"
                                       required
                                       minlength="3"
                                       maxlength="50"
                                       pattern="[a-zA-Z0-9_]+"
                                       autocomplete="username">
                                <small class="text-muted">3-50 caractères, lettres, chiffres et _ uniquement</small>
                            </div>
                            
                            <div class="form-group">
                                <label for="email" class="control-label text-white">Adresse Email</label>
                                <input type="email" 
                                       name="email" 
                                       class="form-control" 
                                       id="email" 
                                       placeholder="Entrez votre email"
                                       value="<?php echo isset($email) ? htmlspecialchars($email, ENT_QUOTES, 'UTF-8') : ''; ?>"
                                       required
                                       autocomplete="email">
                            </div>
                            
                            <div class="form-group">
                                <label for="password" class="control-label text-white">Mot de passe</label>
                                <input type="password" 
                                       name="password" 
                                       class="form-control" 
                                       id="password" 
                                       placeholder="Entrez votre mot de passe"
                                       required
                                       minlength="8"
                                       autocomplete="new-password">
                                <div class="password-strength" id="passwordStrength"></div>
                                <div class="password-requirements">
                                    Min. 8 caractères, 1 majuscule, 1 minuscule, 1 chiffre
                                </div>
                            </div>
                            
                            <div class="form-group">
                                <label for="confirm_password" class="control-label text-white">Confirmer le mot de passe</label>
                                <input type="password" 
                                       name="confirm_password" 
                                       class="form-control" 
                                       id="confirm_password" 
                                       placeholder="Confirmez votre mot de passe"
                                       required
                                       autocomplete="new-password">
                            </div>
                            
                            <div class="form-group">
                                <button type="submit" class="register-btn">
                                    <i class="fa fa-user-plus"></i> S'inscrire
                                </button>
                            </div>
                            
                            <div class="text-center">
                                <a href="admin-login.php" class="text-white">Déjà inscrit ? Se connecter</a>
                                <br><br>
                                <a href="index.php" class="text-white">Retour à l'accueil</a>
                            </div>
                        </form>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="assets/js/jquery/jquery-2.2.4.min.js"></script>
    <script src="assets/js/bootstrap/bootstrap.min.js"></script>
    <script>
        // Validation côté client et indicateur de force du mot de passe
        document.getElementById('password').addEventListener('input', function() {
            const password = this.value;
            const strengthBar = document.getElementById('passwordStrength');
            let strength = 0;
            
            if (password.length >= 8) strength++;
            if (/[A-Z]/.test(password)) strength++;
            if (/[a-z]/.test(password)) strength++;
            if (/[0-9]/.test(password)) strength++;
            if (/[^A-Za-z0-9]/.test(password)) strength++;
            
            strengthBar.className = 'password-strength';
            if (strength <= 1) strengthBar.classList.add('strength-weak');
            else if (strength === 2) strengthBar.classList.add('strength-fair');
            else if (strength === 3) strengthBar.classList.add('strength-good');
            else strengthBar.classList.add('strength-strong');
        });
        
        // Vérification de la correspondance des mots de passe
        document.getElementById('registerForm').addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm_password').value;
            
            if (password !== confirm) {
                e.preventDefault();
                alert('Les mots de passe ne correspondent pas !');
            }
        });
    </script>
</body>
</html>
