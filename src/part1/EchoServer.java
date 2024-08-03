package part1;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private static int keyLength = 2048;
    private DataOutputStream out;
    private DataInputStream in;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    public static void main(String[] args) {
        EchoServer server = new EchoServer();

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the desired key length (e.g., 2048 or 4096): ");
        keyLength = scanner.nextInt();

        System.out.println("Choose a message processing option:");
        System.out.println("1. Sign-then-Encrypt");
        System.out.println("2. Encrypt-then-Sign");
        System.out.println("3. Sign-and-Encrypt");
        int choice = scanner.nextInt();


        server.start(4444);
    }

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) {
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

            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());


            byte[] arr = new byte[2048];
            while (in.read(arr) != -1) {
//                remove all bytes from arr that are empty
                List<Byte> filtered = new ArrayList<>();
                for (byte b : arr) {
                    if (b != 0) {
                        filtered.add(b);
                    }
                }
                byte[] data = new byte[filtered.size()];
                for (int i = 0; i < filtered.size(); i++) {
                    data[i] = filtered.get(i);
                }
                // decrypt data
                String msg = new String(data, StandardCharsets.UTF_8);
                String decryptedMessage = Util.decryptAndVerify(msg, publicKey, privateKey);

                System.out.println("Server received cleartext " + decryptedMessage);
                // encrypt response (this is just the decrypted data re-encrypted)
                String encryptedMessage = Util.encryptAndSign(decryptedMessage, privateKey, publicKey);

                data = encryptedMessage.getBytes(StandardCharsets.UTF_8);
                System.out.println("Server sending ciphertext " + Util.bytesToHex(data));
                out.write(data);
                out.flush();
            }
            stop();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

    }

    /**
     * Close the streams and sockets.
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
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



