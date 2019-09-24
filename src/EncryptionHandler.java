import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.util.Base64;

class EncryptionHandler {


    /**
     * generates a AES 128Bit Secret Key which is then Saved and Encrypted in File as well as returned as SecretKey
     * @param pubKey Path to the RSA Public Key
     * @return AES SecretKey
     */
    SecretKey generateAESandEncryptRSA(Path pubKey, boolean keepUnencryptedAESFile) throws IOException, GeneralSecurityException {
        Path aesKeyFile = Paths.get("aesKey_renameFile.txt");
        Files.deleteIfExists(aesKeyFile);
        Files.createFile(aesKeyFile);
        SecretKey AESKey = AesKeyGenerator.generateKey();
        AesKeyGenerator.saveKey(AESKey, aesKeyFile.toFile());
        encryptAESKeytoFile(aesKeyFile, pubKey, keepUnencryptedAESFile);
        return AESKey;
    }

    SecretKey generateAESandEncryptRSA(Path pubKey, boolean keepUnencryptedAESFile, String timeStamp) throws IOException, GeneralSecurityException {
        Path aesKeyFile = Paths.get("aesKey_" + timeStamp + ".txt");
        Files.deleteIfExists(aesKeyFile);
        Files.createFile(aesKeyFile);
        SecretKey AESKey = AesKeyGenerator.generateKey();
        AesKeyGenerator.saveKey(AESKey, aesKeyFile.toFile());
        encryptAESKeytoFile(aesKeyFile, pubKey, keepUnencryptedAESFile);
        return AESKey;
    }

    /**
     * Decrypts and Loads AES-Key from File for further use in java
     * @param aesKeyFileEnc RSA Encrypted AES-Key-File
     * @param privKey Private Key used for RSA Decryption
     * @return AES SecretKey
     */
    SecretKey decryptAESKeyAndLoad(Path aesKeyFileEnc, Path privKey, boolean keepEncryptedAESFile, boolean keepDecryptedAESFile) throws IOException, GeneralSecurityException {
        decryptAESKeytoFile(aesKeyFileEnc, privKey, keepEncryptedAESFile);
        Path aesKeyFile = Paths.get(aesKeyFileEnc + ".dec");
        SecretKey aesKey = AesKeyGenerator.loadKey(aesKeyFile.toFile());
        if(!keepDecryptedAESFile) Files.deleteIfExists(aesKeyFile);
        return aesKey;
    }

    /**
     * Encrypt a given File with AESKey
     * @param fileToEncrypt File to Encrypt
     * @param AESKey AESKey used for encryption
     */
    void encryptFile(Path fileToEncrypt, SecretKey AESKey) throws IOException, GeneralSecurityException {
        Path fileEncrypted = Paths.get(fileToEncrypt + ".enc");
        Files.deleteIfExists(fileEncrypted);
        Files.createFile(fileEncrypted);
        String aesEncrypted = AesCrypt.encryptSymmetric(Base64.getEncoder().encodeToString(Files.readAllBytes(fileToEncrypt)),
                AESKey);
        Files.write(fileEncrypted,aesEncrypted.getBytes(), StandardOpenOption.APPEND);
        System.out.println("Saved AES-Encrypted File to: " + fileEncrypted.toString());
    }

    /**
     * Decrypt a given File with AESKey
     * @param fileToDecrypt File to Decrypt
     * @param AESKey AESKey used for decryption
     */
    void decryptFile(Path fileToDecrypt, SecretKey AESKey) throws IOException, GeneralSecurityException {
        Path fileDecrypted = Paths.get(fileToDecrypt + ".dec");
        Files.deleteIfExists(fileDecrypted);
        Files.createFile(fileDecrypted);
        String aesDecrypted = new String(Base64.getDecoder().decode(AesCrypt.decryptSymmetric(new String(Files.readAllBytes(fileToDecrypt), StandardCharsets.UTF_8),
                AESKey).getBytes()));
        Files.write(fileDecrypted, aesDecrypted.getBytes(), StandardOpenOption.APPEND);
        System.out.println("Saved AES-Decrypted File to: " + fileDecrypted.toString());
    }

    /**
     * Load the generated AES 128Bit Key from the plaintext File and Encrypt it with the provided
     * RSA Public Key.
     *
     * Save the encrypted Data to aesKey.enc and delete the plaintext aesKey.txt.
     * @param aesKeyFile Path to the aesKeyFile
     * @param pubKey Path to the RSA Public Key
     */
    private void encryptAESKeytoFile(Path aesKeyFile, Path pubKey, boolean keepUnencryptedAESFile) throws IOException, GeneralSecurityException {
        RsaCrypt rsaCrypt = new RsaCrypt();
        byte[] rsaEncrypted = rsaCrypt.encryptData(Files.readAllBytes(aesKeyFile), pubKey.toString());
        Path aesKeyFileEnc = Paths.get(aesKeyFile + ".enc");
        Files.deleteIfExists(aesKeyFileEnc);
        Files.createFile(aesKeyFileEnc);
        Files.write(aesKeyFileEnc, rsaEncrypted, StandardOpenOption.APPEND);
        if(!keepUnencryptedAESFile)Files.deleteIfExists(aesKeyFile);
    }

    /**
     * Load the encrypted AES-Key from File and decrypt to plainText file
     * @param aesKeyFileEnc RSA Encrypted AES-Key File
     * @param privKey RSA PrivateKey for Decryption
     */
    private void decryptAESKeytoFile(Path aesKeyFileEnc, Path privKey, boolean keepEncryptedAESFile) throws IOException, GeneralSecurityException {
        RsaCrypt rsaCrypt = new RsaCrypt();
        byte[] rsaDecrypted = rsaCrypt.decryptData(Files.readAllBytes(aesKeyFileEnc), privKey.toString());
        Path aesKeyFile = Paths.get(aesKeyFileEnc + ".dec");
        Files.deleteIfExists(aesKeyFile);
        Files.createFile(aesKeyFile);
        Files.write(aesKeyFile, rsaDecrypted, StandardOpenOption.APPEND);
        if(!keepEncryptedAESFile)Files.deleteIfExists(aesKeyFileEnc);
    }

}
