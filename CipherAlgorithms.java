import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;



class CaesarCipher {
    /**
     * Encrypts a given text using the Caesar Cipher technique.
     *
     * @param text  The input text to be encrypted.
     * @param shift The number of positions to shift each letter.
     * @return The encrypted text.
     */
    public static String encrypt(String text, int shift) {
        return caesarShift(text, shift); // Calls the shift function with a positive shift value
    }

    /**
     * Decrypts a given text using the Caesar Cipher technique.
     *
     * @param text  The encrypted text to be decrypted.
     * @param shift The number of positions the text was shifted during encryption.
     * @return The decrypted text.
     */
    public static String decrypt(String text, int shift) {
        return caesarShift(text, -shift); // Reverse the shift for decryption
    }

    /**
     * Performs the core Caesar Cipher shift operation.
     *
     * @param text  The input text to be transformed.
     * @param shift The shift value (positive for encryption, negative for decryption).
     * @return The transformed text after applying the shift.
     */
    private static String caesarShift(String text, int shift) {
        StringBuilder result = new StringBuilder();

        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';

                result.append((char) ((c - base + shift + 26) % 26 + base));
            } else {
                result.append(c);
            }
        }

        return result.toString();
    }
}



class VigenereCipher {
    /**
     * Encrypts a given text using the Vigenère Cipher.
     *
     * @param text The input text to be encrypted.
     * @param key  The keyword used for shifting letters.
     * @return The encrypted text.
     */
    public static String encrypt(String text, String key) {
        return vigenereShift(text, key, true); // Calls the shift function with encryption mode
    }

    /**
     * Decrypts a given text using the Vigenère Cipher.
     *
     * @param text The encrypted text to be decrypted.
     * @param key  The keyword used during encryption.
     * @return The decrypted text.
     */
    public static String decrypt(String text, String key) {
        return vigenereShift(text, key, false); // Calls the shift function with decryption mode
    }

    /**
     * Performs the Vigenère Cipher shift operation.
     *
     * @param text    The input text to be transformed.
     * @param key     The keyword used for shifting letters.
     * @param encrypt A boolean indicating whether to encrypt or decrypt.
     * @return The transformed text after applying the Vigenère Cipher.
     */
    private static String vigenereShift(String text, String key, boolean encrypt) {
        StringBuilder result = new StringBuilder();
        key = key.toLowerCase();
        int keyIndex = 0;

        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';
                int shift = key.charAt(keyIndex % key.length()) - 'a';
                shift = encrypt ? shift : -shift;
                result.append((char) ((c - base + shift + 26) % 26 + base));
                keyIndex++;
            } else {
                result.append(c);
            }
        }

        return result.toString(); // Return the final transformed string
    }
}



class AESUtil {
    /**
     * Generates a random 128-bit AES key.
     *
     * @return A SecretKey object for AES encryption.
     * @throws NoSuchAlgorithmException If AES algorithm is not available.
     */
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    /**
     * Encrypts a given text using AES encryption.
     *
     * @param text The plaintext to encrypt.
     * @param key  The AES key used for encryption.
     * @return The encrypted text in Base64 format.
     * @throws Exception If an encryption error occurs.
     */
    public static String encrypt(String text, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypts an AES-encrypted text.
     *
     * @param encryptedText The encrypted text in Base64 format.
     * @param key           The AES key used for decryption.
     * @return The original decrypted plaintext.
     * @throws Exception If a decryption error occurs.
     */
    public static String decrypt(String encryptedText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decrypted);
    }
}


class MorseCipher {
    private static final Map<Character, String> morseMap = new HashMap<>();
    private static final Map<String, Character> reverseMorseMap = new HashMap<>();

    static {

        String[] morseAlphabet = {
                ".-", "-...", "-.-.", "-..", ".", "..-.", "--.", "....", "..", ".---",
                "-.-", ".-..", "--", "-.", "---", ".--.", "--.-", ".-.", "...", "-",
                "..-", "...-", ".--", "-..-", "-.--", "--.."
        };

        for (int i = 0; i < 26; i++) {
            char letter = (char) ('A' + i);
            morseMap.put(letter, morseAlphabet[i]);
            morseMap.put(Character.toLowerCase(letter), morseAlphabet[i]);
            reverseMorseMap.put(morseAlphabet[i], letter);
        }


        for (int i = 0; i <= 9; i++) {
            String firstPart = "-----".substring(0, Math.max(0, 5 - i));
            String secondPart = ".....".substring(0, Math.min(5, i));
            String morseDigit = firstPart + secondPart;

            char digit = (char) ('0' + i);
            morseMap.put(digit, morseDigit);
            reverseMorseMap.put(morseDigit, digit);
        }

        // Space character is represented as "/" in Morse code
        morseMap.put(' ', "/");
        reverseMorseMap.put("/", ' ');
    }

    /**
     * Encrypts a given text into Morse code.
     *
     * @param text The plaintext to be converted.
     * @return The Morse code representation.
     */
    public static String encrypt(String text) {
        StringBuilder morseCode = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (morseMap.containsKey(c)) {
                morseCode.append(morseMap.get(c)).append(" "); // Separate each character with a space
            }
        }
        return morseCode.toString().trim(); // Remove trailing space
    }

    /**
     * Decrypts a given Morse code string into plaintext.
     *
     * @param morseText The Morse code string.
     * @return The decoded plaintext.
     */
    public static String decrypt(String morseText) {
        StringBuilder plainText = new StringBuilder();
        String[] morseWords = morseText.split(" "); // Morse characters are space-separated

        for (String morseChar : morseWords) {
            if (reverseMorseMap.containsKey(morseChar)) {
                plainText.append(reverseMorseMap.get(morseChar));
            }
        }
        return plainText.toString();
    }
}


class ChaCha20Cipher {
    private static final int NONCE_SIZE = 12; // ChaCha20 requires a 12-byte nonce

    /**
     * Encrypts a given plaintext using ChaCha20.
     *
     * @param text  The plaintext to encrypt.
     * @param key   The secret key for encryption.
     * @param nonce A 12-byte nonce (random value).
     * @return The encrypted text in Base64 format.
     */
    public static String encrypt(String text, SecretKey key, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 1)); // Counter starts at 1
        byte[] encrypted = cipher.doFinal(text.getBytes()); // Encrypt the text
        return Base64.getEncoder().encodeToString(encrypted); // Encode to Base64 for easy storage
    }

    /**
     * Decrypts an encrypted text using ChaCha20.
     *
     * @param encryptedText The Base64-encoded encrypted text.
     * @param key           The secret key used for decryption.
     * @param nonce         The same 12-byte nonce used for encryption.
     * @return The decrypted plaintext.
     */
    public static String decrypt(String encryptedText, SecretKey key, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 1)); // Counter must match encryption
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText)); // Decode from Base64 and decrypt
        return new String(decrypted);
    }

    /**
     * Generates a 256-bit (32-byte) ChaCha20 secret key.
     *
     * @return A randomly generated secret key.
     * @throws Exception If key generation fails.
     */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
        keyGen.init(256); // ChaCha20 supports only 256-bit keys
        return keyGen.generateKey();
    }

    /**
     * Generates a secure random 12-byte nonce.
     *
     * @return A new 12-byte nonce.
     */
    public static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce); // Generates cryptographically secure random bytes
        return nonce;
    }
}



public class CipherAlgorithms {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\nChoose an operation: ");
            System.out.println("1. Encrypt");
            System.out.println("2. Decrypt");
            System.out.println("3. Exit");
            System.out.print("> ");

            int operation = getValidInteger(scanner, 1, 3);
            if (operation == 3) {
                System.out.println("Exiting the program. Goodbye!");
                break;
            }

            // Choose cipher
            System.out.println("\nChoose a cipher method: ");
            System.out.println("1. Caesar Cipher");
            System.out.println("2. Vigenere Cipher");
            System.out.println("3. AES Encryption");
            System.out.println("4. Morse Code Cipher");
            System.out.println("5. ChaCha20 Encryption");
            System.out.print("> ");

            int choice = getValidInteger(scanner, 1, 5);
            System.out.print("\nEnter the text: ");
            String text = scanner.nextLine().trim();
            if (text.isEmpty()) {
                System.out.println("Error: Text cannot be empty.");
                continue;
            }

            switch (choice) {
                case 1: // Caesar Cipher
                    System.out.print("Enter shift value: ");
                    int shift = getValidInteger(scanner, Integer.MIN_VALUE, Integer.MAX_VALUE);
                    if (operation == 1) {
                        System.out.println("Encrypted text: " + CaesarCipher.encrypt(text, shift));
                    } else {
                        System.out.println("Decrypted text: " + CaesarCipher.decrypt(text, shift));
                    }
                    break;

                case 2: // Vigenere Cipher
                    System.out.print("Enter keyword: ");
                    String key = scanner.next();
                    if (!key.matches("[a-zA-Z]+")) {
                        System.out.println("Error: The keyword should only contain letters.");
                        continue;
                    }
                    if (operation == 1) {
                        System.out.println("Encrypted text: " + VigenereCipher.encrypt(text, key));
                    } else {
                        System.out.println("Decrypted text: " + VigenereCipher.decrypt(text, key));
                    }
                    break;

                case 3: // AES Encryption
                    if (operation == 1) { // Encryption
                        SecretKey aesKey = AESUtil.generateKey(); // Generate AES key
                        String encodedKey = Base64.getEncoder().encodeToString(aesKey.getEncoded()); // Encode key in Base64

                        String encryptedText = AESUtil.encrypt(text, aesKey); // Encrypt text

                        System.out.println("AES Encrypted: " + encryptedText);
                        System.out.println("Your AES Key (Save this! You will need it for decryption): " + encodedKey);
                    } else { // Decryption


                        System.out.print("Enter AES Key: ");
                        String encodedKey = scanner.nextLine();

                        try {
                            // Decode the provided key and create a SecretKey
                            byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
                            SecretKey aesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

                            // Decrypt the text
                            String decryptedText = AESUtil.decrypt(text, aesKey);
                            System.out.println("AES Decrypted: " + decryptedText);
                        } catch (Exception e) {
                            System.out.println("Error: Invalid key or encrypted text.");
                        }
                    }
                    break;


                case 4: // Morse Code Cipher
                    if (operation == 1) {
                        System.out.println("Morse Code Encrypted: " + MorseCipher.encrypt(text));
                    } else {
                        System.out.println("Morse Code Decrypted: " + MorseCipher.decrypt(text));
                    }
                    break;

                case 5: // ChaCha20 Encryption
                    if (operation == 1) { // Encrypt
                        SecretKey chachaKey = ChaCha20Cipher.generateKey(); // Generate key once
                        byte[] nonce = ChaCha20Cipher.generateNonce(); // Generate nonce
                        String encryptedText = ChaCha20Cipher.encrypt(text, chachaKey, nonce);

                        // Convert key to Base64 for safe storage
                        String encodedKey = Base64.getEncoder().encodeToString(chachaKey.getEncoded());

                        System.out.println("ChaCha20 Encrypted: " + encryptedText);
                        System.out.println("Nonce (Base64, keep this for decryption!): " + Base64.getEncoder().encodeToString(nonce));
                        System.out.println("Secret Key (Base64, keep this safe!): " + encodedKey);
                    } else { // Decrypt
                        System.out.print("Enter nonce (Base64 format): ");
                        byte[] nonceInput;
                        try {
                            nonceInput = Base64.getDecoder().decode(scanner.nextLine());
                        } catch (IllegalArgumentException e) {
                            System.out.println("Error: Invalid nonce format.");
                            continue;
                        }

                        System.out.print("Enter Secret Key (Base64 format): ");
                        byte[] keyBytes;
                        try {
                            keyBytes = Base64.getDecoder().decode(scanner.nextLine());
                        } catch (IllegalArgumentException e) {
                            System.out.println("Error: Invalid key format.");
                            continue;
                        }

                        SecretKey chachaKey = new SecretKeySpec(keyBytes, "ChaCha20");

                        try {
                            String decryptedText = ChaCha20Cipher.decrypt(text, chachaKey, nonceInput);
                            System.out.println("ChaCha20 Decrypted: " + decryptedText);
                        } catch (Exception e) {
                            System.out.println("Decryption failed. Ensure you are using the correct key and nonce.");
                        }
                    }
                    break;

                default:
                    System.out.println("Invalid choice! Please try again.");
            }
        }
        scanner.close();
    }

    private static int getValidInteger(Scanner scanner, int min, int max) {
        while (true) {
            if (scanner.hasNextInt()) {
                int value = scanner.nextInt();
                scanner.nextLine(); // Consume newline
                if (value >= min && value <= max) {
                    return value;
                } else {
                    System.out.print("Invalid input. Please enter a number between " + min + " and " + max + ": ");
                }
            } else {
                System.out.print("Invalid input. Please enter a valid number: ");
                scanner.next(); // Consume invalid input
            }
        }
    }
}
