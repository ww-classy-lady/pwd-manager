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
//1. Set up file to store salt: ..., label: passcode...etc
//Find a way to implement the functionalities detailed in the assignment page (the structure, interactive layout is done)
public class Main {
    private static SecretKeySpec create_key(String new_passphrase, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
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

                SecretKeySpec key = create_key(new_passphrase, salt);

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