import javax.crypto.*;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class RsaCrypt {

    /*
     * Use these Commands to create the RSA Private +  PublicKey in openssl
     *
     * openssl.exe genrsa -out privatekey.pem 4096
     * openssl.exe rsa -in privatekey.pem -out publickey.pem -pubout
     * openssl.exe pkcs8 -in privatekey.pem -topk8 -nocrypt -out privatekey-pkcs8.pem
     * del privatekey.pem
     *
     * */

    /**
     * Encrypts a byte array with a given RSA Public Key with Optimal Asymmetric Encryption Padding using
     * SHA-512 and MGF1
     * @param data Data to be encrypted
     * @param publicKeyFileName Filename of the Public Key in .pem Format --> Please ensure to generate the
     *                          Key using the commands provided above
     * @return Returns the data in Encrypted byte array
     */
    byte[] encryptData(byte[] data, String publicKeyFileName) throws GeneralSecurityException,
            IOException {
        PublicKey publicKey = getPublicKey(publicKeyFileName);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec("SHA-512", "MGF1",
                MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameterSpec);
        return cipher.doFinal(data);
    }

    /**
     * Decrypts a byte array with a given RSA Private Key with Optimal Asymmetric Encryption Padding using
     * SHA-512 and MGF1
     * @param data data to decrypt
     * @param privateKeyFileName Path of the RSA Private Key
     * @return Returns the data in Decrypted byte array
     */
    byte[] decryptData(byte[] data, String privateKeyFileName) throws GeneralSecurityException,
            IOException {
        PrivateKey privateKey = getPrivateKey(privateKeyFileName);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec("SHA-512", "MGF1",
                MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec);
        return cipher.doFinal(data);
    }

    /**
     * Loads a .pem KeyFile using the FileName into a String and adds linebreaks
     * @param filename .pem KeyFile the Key is loaded from.
     * @return String of the Key
     */
    private String getKey(String filename) throws IOException {
        // Read key from file
        String strKeyPEM = "";
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line + "\n";
        }
        br.close();
        return strKeyPEM;
    }

    /**
     * Loads an RSAPrivateKey from a File using the Filename - ready for use in Java
     * @param filename File the Key is loaded from
     * @return RSAPrivateKey
     */
    private RSAPrivateKey getPrivateKey(String filename) throws IOException, GeneralSecurityException {
        String privateKeyPEM = getKey(filename);
        return getPrivateKeyFromString(privateKeyPEM);
    }

    /**
     * Uses the String from getKey Function to load a PrivateKey and edits it to be Java Compatible
     * with the RSAPrivateKey PKCS-8 format
     * @param key Complete String of a PKCS-8 compatible RSA Private Key (.pem format)
     * @return RSAPrivateKey
     */
    private RSAPrivateKey getPrivateKeyFromString(String key) throws GeneralSecurityException {
        String privateKeyPEM = key;
        privateKeyPEM = privateKeyPEM
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        // decode to get the binary DER representation
        byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDER));
        return (RSAPrivateKey) privateKey;
    }

    /**
     * Loads an RSAPublicKey from a File using the Filename - ready for use in Java
     * @param filename the File the Key is loaded from
     * @return RSAPublicKey
     */
    private RSAPublicKey getPublicKey(String filename) throws IOException, GeneralSecurityException {
        String publicKeyPEM = getKey(filename);
        return getPublicKeyFromString(publicKeyPEM);
    }

    /**
     * Uses the String from getKey Function to load a PublicKey and edits it to be Java Compatible
     * with the RSAPublicKey X.509 Format
     * @param key Complete String of a X.509 compatible RSA Public Key (.pem format)
     * @return RSAPublicKey
     */
    private RSAPublicKey getPublicKeyFromString(String key) throws GeneralSecurityException {
        String publicKeyPEM = key;
        publicKeyPEM = publicKeyPEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        // decode to get the binary DER representation
        byte[] publicKeyDER = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDER));
        return (RSAPublicKey) publicKey;
    }
}