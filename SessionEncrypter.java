import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * For Session Encryption
 *
 * Generate Security Parameter key and iv for Session Encryption
 * Mode 1: Generate key and iv form given keylengh
 * Mode 2: Generate key and iv from given key bytes
 */

public class SessionEncrypter {
    SessionKey sessionKey;
    Cipher session;
    byte[] counter;
    IvParameterSpec ivParameterSpec;

    /* Generate key and iv with given KeyLegth */
    public SessionEncrypter(Integer keyLength) throws NoSuchAlgorithmException {
        sessionKey = new SessionKey(keyLength);
        /* generating a initialisation vector (ivBytes), length 16 bytes */
        SecureRandom random = new SecureRandom();
        counter = random.generateSeed(16);
        ivParameterSpec = new IvParameterSpec(counter);
    }
    /* Generate key and iv with given key and iv in byte format */
    public SessionEncrypter(byte[] key,byte[] iv){
        sessionKey = new SessionKey(key);
        ivParameterSpec = new IvParameterSpec(iv);
    }
    /* Output SessionKey */
    public byte[] GetSessionKey(){
        return sessionKey.getSessionKey().getEncoded();
    }
    /* Output IV */
    public byte[] GetIV(){
        return ivParameterSpec.getIV();
    }
    /**
     *  Encrypt session with sessionkey
     *  algorithm: AES
     *  mode: CTR
     *  padding: NoPaddding
     */
    public CipherOutputStream openCipherOutputStream(OutputStream output) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException {
        session = Cipher.getInstance("AES/CTR/NoPadding");
        session.init(Cipher.ENCRYPT_MODE, sessionKey.getSessionKey(), ivParameterSpec);
        return new CipherOutputStream(output,session);
    }
}
