package part1;

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


    public static void main(String[] args) {
        EchoClient client = new EchoClient();

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the desired key length (e.g., 2048 or 4096): ");
        keyLength = scanner.nextInt();

        System.out.println("Choose a message processing option:");
        System.out.println("1. Sign-then-Encrypt");
        System.out.println("2. Encrypt-then-Sign");
        System.out.println("3. Sign-and-Encrypt");
        int choice = scanner.nextInt();

        client.startConnection("127.0.0.1", 4444);
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
    public void startConnection(String ip, int port) {
        try {
            loadOrGenerateKeys();

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
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg) {
        try {
//            // encrypt data
            String encryptedMessage = Util.encryptAndSign(msg, privateKey, publicKey);
            byte[] data = encryptedMessage.getBytes(StandardCharsets.UTF_8);
            System.out.println("Client sending cleartext " + msg);
            System.out.println("Client sending ciphertext " + Util.bytesToHex(data));
            out.write(data);
            out.flush();
            in.read(data);
            // decrypt data
            String reply = new String(data, StandardCharsets.UTF_8);
            String decryptedMessage = Util.decryptAndVerify(reply, publicKey, privateKey);
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

    private static void loadOrGenerateKeys() {
        // Load existing keys or generate new ones if not found
        try {
            File privateKeyFile = new File("private_key.pem");
            File publicKeyFile = new File("public_key.pem");

            if (privateKeyFile.exists() && publicKeyFile.exists()) {
                privateKey = Util.loadPrivateKey("private_key.pem");
                publicKey = Util.loadPublicKey("public_key.pem");
            } else {
                // Generate new key pair
                KeyPair keyPair = Util.generateKeyPair(keyLength);
                privateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();

                // Save the keys to files
                Util.savePrivateKey("private_key.pem", privateKey);
                Util.savePublicKey("public_key.pem", publicKey);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
