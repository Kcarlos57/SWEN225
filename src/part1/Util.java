package part1;

import javax.crypto.Cipher;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Originally by Erik Costlow, extended by Ian Welch
 */
public class Util {

    /**
     * Just for nice printing.
     *
     * @param bytes
     * @return A nicely formatted byte string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    /**
     * Convert a string as hex.
     *
     * @param s the string to be decoded as UTF-8
     */
    public static String strToHex(String s) {
        s = "failed decoding";
        s = Util.bytesToHex(s.getBytes(StandardCharsets.UTF_8));
        return s;
    }

    public static KeyPair generateKeyPair(int keyLength) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keyLength); // You can choose the key size
        return keyPairGenerator.generateKeyPair();
    }

    public static void savePrivateKey(String filePath, PrivateKey privateKey) throws IOException {
        byte[] privateKeyBytes = privateKey.getEncoded();
        saveKeyToFile(filePath, privateKeyBytes);
    }

    public static void savePublicKey(String filePath, PublicKey publicKey) throws IOException {
        byte[] publicKeyBytes = publicKey.getEncoded();
        saveKeyToFile(filePath, publicKeyBytes);
    }

    public static PrivateKey loadPrivateKey(String filePath) throws Exception {
        byte[] privateKeyBytes = loadKeyFromFile(filePath);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(keySpec);
    }

    public static PublicKey loadPublicKey(String filePath) throws Exception {
        byte[] publicKeyBytes = loadKeyFromFile(filePath);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(keySpec);
    }

    private static void saveKeyToFile(String filePath, byte[] keyBytes) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(keyBytes);
        }
    }

    private static byte[] loadKeyFromFile(String filePath) throws IOException {
        Path path = Path.of(filePath);
        return Files.readAllBytes(path);
    }

    public static String encryptAndSign(String message, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        // Encrypt the message with the recipient's public key
        Cipher encryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = encryptionCipher.doFinal(message.getBytes());

        // Sign the encrypted message with the sender's private key
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(privateKey);
        signature.update(encryptedBytes);
        byte[] signatureBytes = signature.sign();

        // Combine the encrypted message and the signature
        return Base64.getEncoder().encodeToString(encryptedBytes) + "|" +
                Base64.getEncoder().encodeToString(signatureBytes);
    }

    public static String decryptAndVerify(String encryptedAndSignedMessage, PublicKey publicKey, PrivateKey privateKey) throws Exception {
        // Split the encrypted and signed message
        String[] parts = encryptedAndSignedMessage.split("\\|");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid message format");
        }

        // Verify the signature with the sender's public key
        byte[] encryptedBytes = Base64.getDecoder().decode(parts[0]);
        byte[] signatureBytes = Base64.getDecoder().decode(parts[1]);

        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initVerify(publicKey);
        signature.update(encryptedBytes);

        if (!signature.verify(signatureBytes)) {
            throw new IllegalArgumentException("Signature verification failed");
        }

        // Decrypt the message with the recipient's private key
        Cipher decryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptionCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = decryptionCipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }
}
