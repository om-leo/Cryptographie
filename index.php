<?php
session_start();

// Génération des clés (alternative si OpenSSL n'est pas disponible)
if (!isset($_SESSION['secret_key']) || !isset($_SESSION['secret_iv'])) {
    try {
        $_SESSION['secret_key'] = base64_encode(random_bytes(32)); // 256 bits
        $_SESSION['secret_iv'] = base64_encode(random_bytes(16));  // 128 bits
    } catch (Exception $e) {
        die("Erreur de génération de clé : " . $e->getMessage());
    }
}

$secretKey = base64_decode($_SESSION['secret_key']);
$secretIv = base64_decode($_SESSION['secret_iv']);

// Chiffrement symétrique (AES-256 alternative)
function encryptData($data, $key, $iv) {
    if (function_exists('openssl_encrypt')) {
        return base64_encode(openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv));
    }
    throw new Exception("OpenSSL extension is required for encryption");
}

function decryptData($encryptedData, $key, $iv) {
    if (function_exists('openssl_decrypt')) {
        return openssl_decrypt(base64_decode($encryptedData), 'aes-256-cbc', $key, 0, $iv);
    }
    throw new Exception("OpenSSL extension is required for decryption");
}

$encryptedText = "";
$decryptedText = "";
$error = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    try {
        if (isset($_POST["encrypt"])) {
            $text = $_POST["text_to_encrypt"] ?? '';
            if (empty($text)) throw new Exception("Le texte à chiffrer est vide");
            $encryptedText = encryptData($text, $secretKey, $secretIv);
        } elseif (isset($_POST["decrypt"])) {
            $text = $_POST["text_to_decrypt"] ?? '';
            if (empty($text)) throw new Exception("Le texte à déchiffrer est vide");
            $decryptedText = decryptData($text, $secretKey, $secretIv);
        }
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Chiffrement Asymétrique (RSA alternative)
$privateKeyFile = __DIR__ . '/private_key.pem';
$publicKeyFile = __DIR__ . '/public_key.pem';

if (!file_exists($privateKeyFile) || !file_exists($publicKeyFile)) {
    if (function_exists('openssl_pkey_new')) {
        $config = [
            "private_key_bits" => 2048,
            "default_md" => "sha256",
        ];
        
        $res = openssl_pkey_new($config);
        if (!$res) {
            throw new Exception("Échec de la génération de clé RSA");
        }
        
        openssl_pkey_export($res, $privateKey);
        $publicKeyDetails = openssl_pkey_get_details($res);
        $publicKey = $publicKeyDetails["key"];
        
        file_put_contents($privateKeyFile, $privateKey);
        file_put_contents($publicKeyFile, $publicKey);
    } else {
        $error = "L'extension OpenSSL est requise pour le chiffrement RSA";
    }
}

$privateKey = file_exists($privateKeyFile) ? file_get_contents($privateKeyFile) : null;
$publicKey = file_exists($publicKeyFile) ? file_get_contents($publicKeyFile) : null;

function encryptWithPublicKey($data, $publicKey) {
    if (function_exists('openssl_public_encrypt')) {
        openssl_public_encrypt($data, $encrypted, $publicKey);
        return base64_encode($encrypted);
    }
    throw new Exception("OpenSSL extension is required for RSA encryption");
}

function decryptWithPrivateKey($encryptedData, $privateKey) {
    if (function_exists('openssl_private_decrypt')) {
        openssl_private_decrypt(base64_decode($encryptedData), $decrypted, $privateKey);
        return $decrypted;
    }
    throw new Exception("OpenSSL extension is required for RSA decryption");
}

$asymEncryptedText = "";
$asymDecryptedText = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    try {
        if (isset($_POST["asym_encrypt"])) {
            $text = $_POST["asym_text_to_encrypt"] ?? '';
            if (empty($text)) throw new Exception("Le texte à chiffrer est vide");
            if (!$publicKey) throw new Exception("Clé publique non disponible");
            $asymEncryptedText = encryptWithPublicKey($text, $publicKey);
        } elseif (isset($_POST["asym_decrypt"])) {
            $text = $_POST["asym_text_to_decrypt"] ?? '';
            if (empty($text)) throw new Exception("Le texte à déchiffrer est vide");
            if (!$privateKey) throw new Exception("Clé privée non disponible");
            $asymDecryptedText = decryptWithPrivateKey($text, $privateKey);
        }
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chiffrement AES-256 / RSA</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            max-width: 600px;
            margin: 50px auto;
            text-align: center;
            background-color: #f4f4f4;
            color: #333;
        }
        h2 {
            color: #2c3e50;
        }
        form {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
        input, button, textarea {
            padding: 12px;
            margin: 10px 0;
            width: 90%;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        button {
            background-color: #3498db;
            color: white;
            border: none;
            font-size: 16px;
            cursor: pointer;
            transition: 0.3s;
        }
        button:hover {
            background-color: #2980b9;
        }
        .output {
            font-weight: bold;
            color: green;
            word-wrap: break-word;
        }
        .error {
            color: red;
            font-weight: bold;
        }
        hr {
            border: 1px solid #ddd;
            margin: 40px 0;
        }
        textarea {
            min-height: 100px;
            resize: vertical;
        }
    </style>
</head>
<body>
    <?php if ($error): ?>
        <div class="error">Erreur : <?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <h2>Chiffrement & Déchiffrement AES-256</h2>

    <form method="post">
        <h3>Chiffrement Symétrique</h3>
        <textarea name="text_to_encrypt" placeholder="Texte à chiffrer" required></textarea>
        <button type="submit" name="encrypt">Chiffrer</button>
    </form>
    <?php if ($encryptedText): ?>
        <p class="output">Texte chiffré : <br><textarea readonly><?= htmlspecialchars($encryptedText) ?></textarea></p>
    <?php endif; ?>

    <form method="post">
        <h3>Déchiffrement Symétrique</h3>
        <textarea name="text_to_decrypt" placeholder="Texte chiffré à déchiffrer" required></textarea>
        <button type="submit" name="decrypt">Déchiffrer</button>
    </form>
    <?php if ($decryptedText): ?>
        <p class="output">Texte déchiffré : <br><textarea readonly><?= htmlspecialchars($decryptedText) ?></textarea></p>
    <?php endif; ?>

    <hr>

    <h2>Chiffrement & Déchiffrement RSA</h2>

    <form method="post">
        <h3>Chiffrement Asymétrique</h3>
        <textarea name="asym_text_to_encrypt" placeholder="Texte à chiffrer" required></textarea>
        <button type="submit" name="asym_encrypt">Chiffrer</button>
    </form>
    <?php if ($asymEncryptedText): ?>
        <p class="output">Texte chiffré : <br><textarea readonly><?= htmlspecialchars($asymEncryptedText) ?></textarea></p>
    <?php endif; ?>

    <form method="post">
        <h3>Déchiffrement Asymétrique</h3>
        <textarea name="asym_text_to_decrypt" placeholder="Texte chiffré à déchiffrer" required></textarea>
        <button type="submit" name="asym_decrypt">Déchiffrer</button>
    </form>
    <?php if ($asymDecryptedText): ?>
        <p class="output">Texte déchiffré : <br><textarea readonly><?= htmlspecialchars($asymDecryptedText) ?></textarea></p>
    <?php endif; ?>

    <?php if (!function_exists('openssl_encrypt')): ?>
        <div class="error" style="margin-top: 20px;">
            Attention : L'extension OpenSSL n'est pas activée. Certaines fonctionnalités ne sont pas disponibles.
        </div>
    <?php endif; ?>
</body>
</html>