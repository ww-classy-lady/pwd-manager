import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;


//TODO:
/*
 * 1. Store a hard coded token
 * (we do not ask user if file exist or not, we check that)
 * 2. If file does not exist,
 * a) create the file,
 * b) ask user for passphrase to file
 * c) create a new salt
 * d) store salt: encrypted token pair (token encrypted using key [generated using user's passphrase and salt]))
 * 3. If file does exist, using salt stored in file(byte[]) and user's entered passphrase to generate a key (secretkeyspec)
 * Use that key to decrypt the encrypted token (stored in the file) and see if that value equals string token (private var)
 * a) If decrypted token == string token, then allow user to add, read, or quit.
 * b) Else, throw an error or exception for wrong passphrase
 */
public class Main {
    private static String token = "wendy";

    // String base64Encoded =  encrypt(key, plaintext)
    // String decrypt(key, encryptedBase64EncodedText), returns clear text

    private static SecretKeySpec createKey(String new_passphrase, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeySpec spec = new PBEKeySpec(new_passphrase.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);
        byte [] encoded_key = sharedKey.getEncoded();
        SecretKeySpec key = new SecretKeySpec(encoded_key, "AES");
        return key;
    }
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //Main menu
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the passcode to access your passwords: ");
        String passphrase = scanner.nextLine();
        File file = new File("src/passwords.txt");

        if (file.exists()) {
            System.out.println("File exists");
        } else {
            System.out.println("No password file detected. Creating a new password file.");
            try {
                file.createNewFile();
                System.out.println("File Created");


                SecureRandom random = new SecureRandom();
                byte[] salt = new byte[16];
                random.nextBytes(salt);

                String encoded_salt = Base64.getEncoder().encodeToString(salt);

                System.out.print("Enter your new passphrase: ");
                String new_passphrase = scanner.nextLine();

                SecretKeySpec key = createKey(new_passphrase, salt);

                // Take the key, encrypt the token
                // Store the salt and the token in the first line

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        while(true) {
            System.out.println("a: Add Password");
            System.out.println("r: Read Password");
            System.out.println("q. Quit");
            System.out.print("Enter choice: ");
            String choice = scanner.nextLine();
            switch(choice) {
                case "a":
                    System.out.print("Enter label for password: ");
                    String label = scanner.nextLine();
                    System.out.print("Enter password to store: ");
                    String password = scanner.nextLine();
                    break;
                case "r":
                    System.out.print("Enter label for password: ");
                    String label2 = scanner.nextLine();
                    //TODO: finding passcode from file based on provided label
                    // if label does not exist, return not found or some error
                    System.out.println("Found: //TODO! ");
                    break;
                case "q":
                    System.out.println("Quitting");
                    System.exit(0);
            }
        }
    }
}