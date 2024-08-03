package part2;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
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

    public static KeyPair getKeyPair(String keystoreFile, String keystorePassword, String alias, String keyPassword) throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        FileInputStream keystoreStream = new FileInputStream(keystoreFile);
        keystore.load(keystoreStream, keystorePassword.toCharArray());
        // Load the private key
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(alias, new KeyStore.PasswordProtection(keyPassword.toCharArray()));
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        // Get the public key certificate for the client
        Certificate clientCert;
        try {
            clientCert = keystore.getCertificate(alias);
        } catch (KeyStoreException e) {
            System.out.println("Error getting the client certificate: " + e.getMessage());
            return null;
        }
        // Load the corresponding public key
        PublicKey publicKey = clientCert.getPublicKey();

        return new KeyPair(publicKey, privateKey);
    }

}
