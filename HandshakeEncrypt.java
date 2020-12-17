import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Encrypt SessionKey and Session IV in "Session" handshake message
 * Algorithm: RSA
 * Secret Key: Client's public key
 */
public class HandshakeEncrypt {
    public static byte[] HandshakeEncrypt(byte[] plaintext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher HandshakeMessage = Cipher.getInstance("RSA");
        HandshakeMessage.init(Cipher.ENCRYPT_MODE,key);
        return HandshakeMessage.doFinal(plaintext);
    }
}
