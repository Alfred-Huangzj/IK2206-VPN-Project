import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * For Session Decryption
 *
 * Generate Security Parameter key and iv for Session Encryption
 * Mode: Generate key and iv from given key bytes
 */
public class SessionDecrypter {
    SessionKey sessionKey;
    Cipher session;
    byte[] decodedIV;

    public SessionDecrypter(byte[] key,byte[] iv){
        sessionKey = new SessionKey(key);
        decodedIV = iv;
    }
    CipherInputStream openCipherInputStream(InputStream input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        session = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(decodedIV);
        session.init(Cipher.DECRYPT_MODE, sessionKey.getSessionKey(), ivParameterSpec);
        return new CipherInputStream(input, session);
    }
}
