package part3;

import part2.EchoServer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class EchoClient {

    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static int keyLength = 2048;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private SecretKey aesKey;


    public static void main(String[] args) {
        // Check the number of arguments
        if (args.length != 1) {
            System.out.println("Usage: java Client <keystore password>");
            return;
        }
        EchoClient client = new EchoClient();

        String password = args[0];

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the desired key length (e.g., 2048 or 4096): ");
        keyLength = scanner.nextInt();

        System.out.println("Choose a message processing option:");
        System.out.println("1. Sign-then-Encrypt");
        System.out.println("2. Encrypt-then-Sign");
        System.out.println("3. Sign-and-Encrypt");
        int choice = scanner.nextInt();

        client.startConnection("127.0.0.1", 4444, password);
        client.sendAesKey();
        client.sendMessage("12345678");
        client.sendMessage("ABCDEFGH");
        client.sendMessage("87654321");
        client.sendMessage("HGFEDCBA");
        client.stopConnection();
    }

    /**
     * Setup the two way streams.
     *
     * @param ip   the address of the server
     * @param port port used by the server
     */
    public void startConnection(String ip, int port, String password) {
        try {
            loadOrGenerateKeys(password);

            // Print the public key as is (encoded)
            String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            System.out.println("Public Key (Encoded): " + encodedPublicKey);

            // If it's an RSAPublicKey, you can print modulus and exponent
            if (publicKey instanceof RSAPublicKey rsaPublicKey) {
                System.out.println("Modulus: " + rsaPublicKey.getModulus());
                System.out.println("Exponent: " + rsaPublicKey.getPublicExponent());
            }

            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (Exception e) {
            System.out.println("Error when initializing connection");
        }
    }

    public void sendAesKey() {
        try {
            // Generate a random AES key for symmetric encryption
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            aesKey = keygen.generateKey();

            // Encrypt the AES key with the server's public key using RSA
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
            // Send the encrypted AES key to the server
            out.writeInt(encryptedAesKey.length);
            out.write(encryptedAesKey);
            receiveAesKey();
        } catch (Exception e){
            System.out.println(e.getMessage());
        }
    }

    public void receiveAesKey() throws Exception {
        // Receive the encrypted AES key from the client
        int keyLength = in.readInt();
        byte[] encryptedAesKey = new byte[keyLength];
        in.readFully(encryptedAesKey);

        // Decrypt the AES key with the server's private key using RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);

        // Convert the AES key bytes to a secret key object
        SecretKey receivedAesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // check whether the received aesKey matches the sent one
        assert receivedAesKey.equals(aesKey);
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg) {
        try {

//            // encrypt data
            SecretKey derivedKey = Util.deriveKey(aesKey, "server-client");
            String encryptedMessage = Util.encryptAndSign(msg, privateKey, derivedKey);
            byte[] data = encryptedMessage.getBytes(StandardCharsets.UTF_8);
            System.out.println("Client sending cleartext " + msg);
            System.out.println("Client sending ciphertext " + Util.bytesToHex(data));
            out.write(data);
            out.flush();
            in.read(data);
            // decrypt data
            String reply = new String(data, StandardCharsets.UTF_8);
            String decryptedMessage = Util.decryptAndVerify(reply, publicKey, derivedKey);
            System.out.println("Server returned cleartext " + decryptedMessage);
            return decryptedMessage;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    /**
     * Close down our streams.
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }

    private static void loadOrGenerateKeys(String password) throws Exception {

        // Get the directory containing the source code file
        String sourceDirectory = EchoServer.class.getProtectionDomain().getCodeSource().getLocation().getPath();

        // Specify the relative path to the keystore file
        String relativePath = "part3/cybr372.jks";

        // Create a File object with the source directory and relative path
        File file = new File(sourceDirectory, relativePath);

        // Get the absolute path of the file
        String absolutePath = file.getAbsolutePath();

        KeyPair clientKeyPair = part2.Util.getKeyPair(absolutePath, password, "server-client", password);
        assert clientKeyPair != null;
        privateKey = clientKeyPair.getPrivate();
        publicKey = clientKeyPair.getPublic();
    }
}
