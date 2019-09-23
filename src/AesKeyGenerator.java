import static org.apache.commons.codec.binary.Hex.*;
import static org.apache.commons.io.FileUtils.*;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;

class AesKeyGenerator {

    private static final String SYMMETRIC_ALGORITHM = "AES";

    /**
     * Generates a AES 128Bit Key for use in AES Encryption
     * @return The AES SecretKey
     */
    static SecretKey generateKey() throws NoSuchAlgorithmException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        keyGenerator.init(128); // 128 default; 192 and 256 also possible
        return keyGenerator.generateKey();
    }

    /**
     * Save a SecretKey to a specified File.
     * It will be saved in form of a char array encoded in hex
     *
     * @param key Key to be saved
     * @param file File the Key is saved to
     */
    static void saveKey(SecretKey key, File file) throws IOException
    {
        char[] hex = encodeHex(key.getEncoded());
        BufferedWriter writer = new BufferedWriter(new FileWriter(file));
        writer.write(String.valueOf(hex));
        writer.close();
    }

    /**
     * Load an AES SecretKey from a specified File.
     *
     * The Key in the File has to be in form of a char array encoded in HEX
     *
     * @param file The File the Key should be loaded from
     * @return Returns a AES SecretKeySpec with the encoded Key
     */
    static SecretKey loadKey(File file) throws IOException
    {
        String data = new String(readFileToByteArray(file));
        byte[] encoded;
        try {
            encoded = decodeHex(data.toCharArray());
        } catch (DecoderException e) {
            e.printStackTrace();
            return null;
        }
        return new SecretKeySpec(encoded, SYMMETRIC_ALGORITHM);
    }
}
