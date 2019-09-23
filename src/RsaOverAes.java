import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.ParseException;

public class RsaOverAes {

    private final static String helpArgumentText = "RSAoverAES Version 1.0.2\n\n" +
            "This Programm Outputs a 128 Bit AES-KEY in GCM Mode with No Padding,\nwhich is then " +
            "Encrypted via the RSA Pbulic Key Algorithm.\n" +
            "Optionally you can specify a file which is encrypted with the 128 Bit AES Key\nthat " +
            "will then be saved encrypted via RSA.\n\n" +
            "CommandLine Arguments:\n" +
            "\n" +
            " -encrypt Set Mode to Generate RSA encrypted AES File and encrypt File\n" +
            " -fileToEncrypt Specify a File to be Encrypted via AES/GCM/NoPadding - 128Bit\n" +
            " -pubKey Specify a RSA-Public Key to encrypt the AES KeyFile with (mandatory with -encrypt)\n" +
            "\n" +
            " -decrypt Set Mode to decrypt the AESKey File using RSA Private Key and decrypt File\n" +
            " -fileToDecrypt Specify a File to Decrypt\n" +
            " -aesKey Specify the RSA/OAEP/SHA512withMGF1 Encrypted AES-Key File to decrypt (mandatory with -decrypt)\n" +
            " -privKey Specify the RSA Private key for decrypting the AES-Key File (mandatory with -decrypt)\n" +
            "\n" +
            "* Use these Commands to create the RSA Private-PKCS8 +  PublicKey in openssl\n" +
            "\n" +
            "     * openssl genrsa -out privatekey.pem 4096\n" +
            "     * openssl rsa -in privatekey.pem -out publickey.pem -pubout\n" +
            "     * openssl pkcs8 -in privatekey.pem -topk8 -nocrypt -out privatekey-pkcs8.pem\n" +
            "     * rm privatekey.pem\n" +
            "\n"
            +"For more Information see: https://github.com/eXspir3/RSAoverAES";

    private final static String greeting =
            "\n\n===================================================\n" +
                    "RSAoverAES Version 1.0.2 - Author: Philipp Ensinger\n" +
                    "===================================================\n";
    private final static boolean keepFile = true;
    private final static boolean deleteFile = false;

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        EncryptionHandler rsaOverAesHandler = new EncryptionHandler();
        Path pubKey;
        Path fileToEncrypt;
        Path privKey;
        Path fileToDecrypt;
        Path aesKey;
        CommandLine commandLine;

        System.out.println(greeting);
        Option option_help = Option.builder("help").required(false).desc("Show HelpPage").build();
        Option option_encrypt = Option.builder("encrypt").required(false).desc("Set Mode to Generate RSA encrypted AES File and encrypt File").build();
        Option option_decrypt = Option.builder("decrypt").required(false).desc("Set Mode to decrypt the AESKey File using RSA Private Key and decrypt File").build();
        Option option_pubKey = Option.builder("pubKey").required(false).desc("Set RSA PublicKey").hasArg().build();
        Option option_privKey = Option.builder("privKey").required(false).desc("Set RSA privateKey").hasArg().build();
        Option option_aesKey = Option.builder("aesKey").required(false).desc("Set Encrypted AES-Key File to decrypt").hasArg().build();
        Option option_fileToEncrypt = Option.builder("fileToEncrypt").required(false).desc("Specify a File to Encrypt").hasArg().build();
        Option option_fileToDecrypt = Option.builder("fileToDecrypt").required(false).desc("Specify a File to Decrypt").hasArg().build();

        Options options = new Options();
        CommandLineParser parser = new DefaultParser();
        options.addOption(option_pubKey);
        options.addOption(option_privKey);
        options.addOption(option_aesKey);
        options.addOption(option_fileToEncrypt);
        options.addOption(option_fileToDecrypt);
        options.addOption(option_help);
        options.addOption(option_encrypt);
        options.addOption(option_decrypt);


        try {
            commandLine = parser.parse(options, args);
            if (commandLine.hasOption("help")) {
                System.out.println(helpArgumentText);
                System.exit(0);
            }
            if (commandLine.hasOption("encrypt")) {
                if (commandLine.hasOption("pubKey") && commandLine.hasOption("fileToEncrypt")) {
                    pubKey = Paths.get(commandLine.getOptionValue("pubKey"));
                    System.out.println("Generating RSA-Encrypted AES-KeyFile");
                    System.out.println("Using RSA PublicKey to encrypt AES-KeyFile: " + pubKey.toString());
                    /*
                     * Generate and save the AES Key RSA encrypted to File.
                     */

                    SecretKey AESKey = rsaOverAesHandler.generateAESandEncryptRSA(pubKey, deleteFile, getCurrentTimeStamp());

                    /*
                     * Encrypt the provided File using AESKey
                     */

                    fileToEncrypt = Paths.get(commandLine.getOptionValue("fileToEncrypt"));
                    System.out.println("Encrypting File: " + fileToEncrypt.toString() + " with AES-128 GCM / NOPadding");
                    rsaOverAesHandler.encryptFile(fileToEncrypt, AESKey);

                } else if (commandLine.hasOption("pubKey")) {
                    pubKey = Paths.get(commandLine.getOptionValue("pubKey"));
                    System.out.println("Generating RSA-Encrypted AES-KeyFile");
                    System.out.println("Using RSA PublicKey to encrypt AES-KeyFile: " + pubKey.toString());

                    /*
                     * Generate and save the AES Key RSA encrypted to File.
                     */
                    rsaOverAesHandler.generateAESandEncryptRSA(pubKey, deleteFile, getCurrentTimeStamp());
                    System.out.println("Only generated RSA Encrypted AES-Key-File as no -fileToEncrypt was specified");
                } else {
                    throw new ParseException("At least -pubKey has to be specified when using -encrypt\nBe sure to pay Attention to case-sensitivity!");
                }
            }

            if (commandLine.hasOption("decrypt")) {
                if (commandLine.hasOption("privKey") && commandLine.hasOption("aesKey") && commandLine.hasOption("fileToDecrypt")) {
                    privKey = Paths.get(commandLine.getOptionValue("privKey"));
                    aesKey = Paths.get(commandLine.getOptionValue("aesKey"));
                    System.out.println("Decrypting RSA Encrypted AES-Key-File: " + aesKey.toString());
                    System.out.println("Using RSA PrivateKey to decrypt AES-KeyFile: " + privKey.toString());

                    /*
                     * Decrypt AES-Key and save to File unencrypted
                     */

                    SecretKey AESKey = rsaOverAesHandler.decryptAESKeyAndLoad(aesKey, privKey, keepFile, deleteFile);

                    /*
                     * Decrypt the provided File using AESKey
                     */
                    fileToDecrypt = Paths.get(commandLine.getOptionValue("fileToDecrypt"));
                    rsaOverAesHandler.decryptFile(fileToDecrypt, AESKey);

                } else if (commandLine.hasOption("privKey") && commandLine.hasOption("aesKey")) {
                    privKey = Paths.get(commandLine.getOptionValue("privKey"));
                    aesKey = Paths.get(commandLine.getOptionValue("aesKey"));
                    System.out.println("Decrypting RSA Encrypted AES-Key-File: " + aesKey.toString());
                    System.out.println("Using RSA PrivateKey to decrypt AES-KeyFile: " + privKey.toString());

                    /*
                     * Decrypt and save the decrypted AES Key to File.
                     */

                    rsaOverAesHandler.decryptAESKeyAndLoad(aesKey, privKey, keepFile, keepFile);

                    System.out.println("Only decrypted RSA Encrypted AES-Key-File as no -fileToDecrypt was specified");
                } else {
                    throw new ParseException("At least -privKey and -aesKey has to be specified when using -decrypt\nBe sure to pay Attention to case-sensitivity!");
                }
            }


        } catch (ParseException exception) {
            System.out.print("Parse error: ");
            System.out.println(exception.getMessage());
            System.exit(-1);
        }
    }
    private static String getCurrentTimeStamp() {
        SimpleDateFormat sdfDate = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss");
        Date now = new Date();
        return sdfDate.format(now);
    }
}
