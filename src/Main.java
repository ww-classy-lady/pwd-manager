import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
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
    private static String token = "wendylauren";

    // String base64Encoded =  encrypt(key, plaintext)
    // String decrypt(key, encryptedBase64EncodedText), returns clear text

    private static String encrypt(SecretKeySpec key, String plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedData = cipher.doFinal(plaintext.getBytes());
        return new String(Base64.getEncoder().encode(encryptedData));
    }

    private static String decrypt(SecretKeySpec key, String encryptedBase64EncodedText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decoded = Base64.getDecoder().decode(encryptedBase64EncodedText);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }

    private static SecretKeySpec createKey(String new_passphrase, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeySpec spec = new PBEKeySpec(new_passphrase.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);
        byte [] encoded_key = sharedKey.getEncoded();
        SecretKeySpec key = new SecretKeySpec(encoded_key, "AES");
        return key;
    }

    private static void writeToFile(File file, String left, String right) throws IOException {
        FileWriter fr = new FileWriter(file, true);
        fr.write(left + ":" + right);
        fr.close();
    }

    // private static String readLine(file, )
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        //Main menu
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the passcode to access your passwords: ");
        String passphrase = scanner.nextLine();
        File file = new File("src/passwords.txt");

        if (file.exists()) {
            System.out.println("File exists");
            // extract salt
            // make new key
            // use key to decrypt token
            // check if token is same
            BufferedReader br = new BufferedReader(new FileReader("src/passwords.txt"));
            String firstLine = br.readLine();
            String encodedSalt = firstLine.substring(0, firstLine.indexOf(":"));
            byte[] salt = Base64.getDecoder().decode(encodedSalt);
            SecretKeySpec key = createKey(passphrase, salt);
            String encodedToken = firstLine.substring(firstLine.indexOf(":")+1);
            String decryptedToken = decrypt(key, encodedToken);

            if (token.equals(decryptedToken)){
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
            } else {
            }


        } else {
            System.out.println("No password file detected. Creating a new password file.");
            try {
                file.createNewFile();
                System.out.println("File Created");

                SecureRandom random = new SecureRandom();
                byte[] salt = new byte[16];
                random.nextBytes(salt);
                String encodedSalt = Base64.getEncoder().encodeToString(salt);

                System.out.print("Enter your new passphrase: ");
                String new_passphrase = scanner.nextLine();

                SecretKeySpec key = createKey(new_passphrase, salt);
                String encryptedToken = encrypt(key, token);

                writeToFile(file, encodedSalt, encryptedToken);


                // Take the key, encrypt the token
                // Store the salt and the token in the first line

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}