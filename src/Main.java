import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

//Group Members: Lauren Eterno, Wendy Wu
//Assignment 1 Password Manager CSDS 444
//Date: 9/26/2024
public class Main {
    private static String token = "wendylauren";

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
        BufferedReader reader = new BufferedReader(new FileReader("passwords.txt"));
        List<String> allLinesInFile = new ArrayList<>();
        String line = reader.readLine();
        String pair = left + ":" + right;
        boolean updated = false;
        while(line != null) {
            if (line.substring(0, line.indexOf(":")).equals(left)) {
                String oldRight = line.substring(line.indexOf(":") + 1);
                pair = line.replace(oldRight, right);
                allLinesInFile.add(pair);
                updated = true;
            }
            else{
                allLinesInFile.add(line);
            }
            line = reader.readLine();
        }
        reader.close();
        if (!updated) {
            FileWriter writer = new FileWriter("passwords.txt", true);
            writer.write(pair);
            writer.write("\n");
            writer.close();
        }
        else{
            FileWriter writer = new FileWriter("passwords.txt");
            StringBuilder fileContent = new StringBuilder();
            for(String currentLine: allLinesInFile)
            {
                fileContent.append(currentLine).append("\n");
            }
            writer.write(fileContent.toString());
            writer.close();
        }
    }
    private static String readFromFile(File file, SecretKeySpec key, String label) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        BufferedReader br = new BufferedReader(new FileReader("passwords.txt"));
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

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        //Main menu
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the passcode to access your passwords: ");
        String passphrase = scanner.nextLine();
        File file = new File("passwords.txt");
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


            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        else {
            //file exists now
            BufferedReader br = new BufferedReader(new FileReader("passwords.txt"));
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
        //file does not exist, but we created a new file
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