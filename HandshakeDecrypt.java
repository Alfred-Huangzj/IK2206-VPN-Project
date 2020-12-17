import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.management.loading.PrivateClassLoader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Decrypt encrypt session message from Server
 * Algorithm: RSA
 * Secret Key: Client Secret Key
 */
public class HandshakeDecrypt {
    public static byte[] HandshakeDecrypt(byte[] ciphertext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher HandshakeMessage = Cipher.getInstance("RSA");
        HandshakeMessage.init(Cipher.DECRYPT_MODE,key);
        return HandshakeMessage.doFinal(ciphertext);
    }
    public static PrivateKey getPrivateKey(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(keyfile);
        byte [] privateKeyByte = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
