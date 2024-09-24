import java.util.Scanner;

//TODO:
//1. Set up file to store salt: ..., label: passcode...etc
//Find a way to implement the functionalities detailed in the assignment page (the structure, interactive layout is done)
public class Main {
    public static void main(String[] args) {
        //Main menu
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the passcode to access your passwords: ");
        String passphrase = scanner.nextLine();
        String filePass = "pass"; //TODO: must change this to the password form for the file
        //QUESTION FOR Office HOUR: file exist if passcode is correct & exist right?
        //file does not exist if the existing password variable is empty/null?
        if(passphrase.equals(filePass)) {
            System.out.println("File exist");
        }
        else{
            System.out.println("No password file detected. Creating a new password file.");
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