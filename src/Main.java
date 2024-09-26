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
        try{
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] encryptedData = cipher.doFinal(plaintext.getBytes());
            return new String(Base64.getEncoder().encode(encryptedData));
        } catch(Exception e){
            System.out.println("ERROR IN ENCRYPT: " + e.getMessage());
        }
        return null;
    }

    private static String decrypt(SecretKeySpec key, String encryptedBase64EncodedText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decoded = Base64.getDecoder().decode(encryptedBase64EncodedText);
            byte[] decrypted = cipher.doFinal(decoded);
            return new String(decrypted);
        }catch (Exception e) {
            System.out.println("ERROR in DECRYPT: " + e.getMessage());
        }
        return null;
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
        fr.write("\n");
        fr.close();
    }
    private static String readFromFile(File file, SecretKeySpec key, String label) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        BufferedReader br = new BufferedReader(new FileReader("src/passwords.txt"));
        String line = br.readLine();
        while(line != null) {
            if (line.substring(0, line.indexOf(":")).equals(label)) {
                String encryptedPassword = line.substring(line.indexOf(":") + 1);
                return decrypt(key, encryptedPassword);
            }
            line = br.readLine();
        }
        br.close();
        return null;
    }
    // private static String readLine(file, )
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        //Main menu
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the passcode to access your passwords: ");
        String passphrase = scanner.nextLine();
        File file = new File("src/passwords.txt");
        SecretKeySpec key;

        if (!file.exists()) {
            System.out.println("No password file detected. Creating a new password file.");
            try {
                file.createNewFile();
                SecureRandom random = new SecureRandom();
                byte[] salt = new byte[16];
                random.nextBytes(salt);
                String encodedSalt = Base64.getEncoder().encodeToString(salt);

                key = createKey(passphrase, salt);
                String encryptedToken = encrypt(key, token);

                writeToFile(file, encodedSalt, encryptedToken);

                // Take the key, encrypt the token
                // Store the salt and the token in the first line

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        else {
            //file exists now
            BufferedReader br = new BufferedReader(new FileReader("src/passwords.txt"));
            String firstLine = br.readLine();
            String encodedSalt = firstLine.substring(0, firstLine.indexOf(":"));
            byte[] salt = Base64.getDecoder().decode(encodedSalt);
            key = createKey(passphrase, salt);
            String encodedToken = firstLine.substring(firstLine.indexOf(":") + 1);
            String decryptedToken = decrypt(key, encodedToken);
            if (!token.equals(decryptedToken)) {
                //User entered wrong password that does not successfully decrypt our token to its original form/value
                System.out.println("Error: The password you have entered is incorrect.");
                System.exit(0);
            }
        }
        //file does not exist but we created a new file
        //or file exists and token equals decrypted token
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
                    String encryptedPass = encrypt(key, password);
                    writeToFile(file, label, encryptedPass);
                    System.out.println("Successful ADD operation - Password stored");
                    break;
                case "r":
                    System.out.print("Enter label for password: ");
                    String label2 = scanner.nextLine();
                    //TODO: finding passcode from file based on provided label
                    // if label does not exist, return not found or some error
                    String decryptedPass = readFromFile(file, key, label2);
                    if(decryptedPass == null) {
                        System.out.println("Failed READ operation - Password not found with this label");
                    }
                    else {
                        System.out.println("Found: " + decryptedPass);
                    }
                    break;
                case "q":
                    System.out.println("Quitting");
                    System.exit(0);
            }
        }

    }
}