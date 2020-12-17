import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class SessionKey {
    public SecretKey AesKey;


    /**
     * Generate a Key
     * algorithm: AES
     * Mode 1: Generate form given key length
     * Mode 2: Generate form given key bytes
     *
     */

    /* Generate AseKey with a given key length */
    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        KeyGenerator KeyGen = KeyGenerator.getInstance("AES");
        KeyGen.init(keylength);
        AesKey = KeyGen.generateKey();
    }
    /* Generate AseKey with given key bytes */
    public SessionKey(byte[] keybytes){
        AesKey = new SecretKeySpec(keybytes,"AES");
    }
    /* Transfer  */

    /* Output Session key*/
    public SecretKey getSessionKey(){
        return AesKey;
    }

}
