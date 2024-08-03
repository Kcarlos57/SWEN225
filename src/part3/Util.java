package part3;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
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
        try {
            s = Util.bytesToHex(s.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            System.out.println("Unsupported Encoding Exception");
        }
        return s;
    }

    public static String encryptAndSign(String message, PrivateKey privateKey, SecretKey aesKey) throws Exception {
        // Encrypt the message with the recipient's public key
        Cipher encryptionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, aesKey);
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

    public static String decryptAndVerify(String encryptedAndSignedMessage, PublicKey publicKey, SecretKey aesKey) throws Exception {
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
        Cipher decryptionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        decryptionCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decryptedBytes = decryptionCipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    // A method to derive a key from a master key and a label using HMAC-SHA256
    public static SecretKey deriveKey(SecretKey masterKey, String label) throws Exception {
        // Create a Mac instance with the HMAC-SHA256 algorithm
        Mac mac = Mac.getInstance("HmacSHA256");

        // Initialize the Mac with the master key
        mac.init(masterKey);

        // Compute the Mac on the label
        byte[] macBytes = mac.doFinal(label.getBytes());

        // Convert the Mac bytes to a secret key object
        return new SecretKeySpec(macBytes, "AES");
    }
}
