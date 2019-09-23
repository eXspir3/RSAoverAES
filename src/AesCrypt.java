import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;


class AesCrypt {

    private static final String SYMMETRIC_ALGORITHM_WITH_MODE_AND_PADDING = "AES/GCM/NoPadding";
    private static final int IV_SIZE_IN_BYTES_FOR_GCM = 12;
    private static final String CHAR_COLON = ":";

    private static Cipher getSymmetricCipher( int mode, SecretKey secretKey, byte[] initializeVectorBytes ) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance( SYMMETRIC_ALGORITHM_WITH_MODE_AND_PADDING );
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, initializeVectorBytes );
        cipher.init( mode, secretKey, parameterSpec );
        return cipher;
    }

    static String encryptSymmetric(String plainText, SecretKey secretKey ) throws GeneralSecurityException {
        byte[] initializeVectorBytes = generateRandom( IV_SIZE_IN_BYTES_FOR_GCM );
        final Cipher cipher = getSymmetricCipher( Cipher.ENCRYPT_MODE, secretKey, initializeVectorBytes );
        byte[] cipherTextBytes = cipher.doFinal( plainText.getBytes(StandardCharsets.UTF_8) );
        return Base64.getEncoder().encodeToString( initializeVectorBytes ) + CHAR_COLON + Base64.getEncoder().encodeToString( cipherTextBytes );
    }

    static String decryptSymmetric(String base64CipherTextString, SecretKey secretKey ) throws GeneralSecurityException {
        byte[] initializeVectorBytes = Base64.getDecoder().decode( base64CipherTextString.substring( 0, base64CipherTextString.indexOf( CHAR_COLON ) ) );
        final Cipher cipher = getSymmetricCipher( Cipher.DECRYPT_MODE, secretKey, initializeVectorBytes );
        byte[] plainTextBytes = cipher.doFinal( Base64.getDecoder().decode( base64CipherTextString.substring( base64CipherTextString.indexOf( CHAR_COLON ) + 1 ) ) );
        return new String( plainTextBytes, StandardCharsets.UTF_8);
    }

    private static byte[] generateRandom( int length ) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[ length ];
        secureRandom.nextBytes( randomBytes );
        return randomBytes;
    }
}