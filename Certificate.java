import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Certificate {
    /* Get Details in Certificate file */
    public static X509Certificate getCertificate(String FileName) throws CertificateException, FileNotFoundException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream file = new FileInputStream(FileName);
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(file);
        return cert;
    }
    /**
     *  Verify Certificate
     *  -Check Valid date
     *  -Check Signature
     */
    public static void verifyCertificate(String flag, String CAFileName, X509Certificate User){
        try {
            X509Certificate CA = getCertificate(CAFileName);
            CA.checkValidity();
            User.checkValidity();
            CA.verify(CA.getPublicKey());
            User.verify(CA.getPublicKey());
            Logger.log(flag + " verify successfully.");
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

    }
    /**
     * Certificate encoding takes place in two steps:
     * 1. encode the certificate in DER format
     * 2. encode the result as a string using Base64-encoding
     */
    public static String encodeCertificate(X509Certificate cert) throws CertificateEncodingException {
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }
    /**
     *
     */
    public static X509Certificate decodeCertificate (String encodeCertificate){
        X509Certificate cert = null;
        try {
            CertificateFactory certificateFactory = null;
            certificateFactory = CertificateFactory.getInstance("X.509");
            byte[] CertificateByte = Base64.getDecoder().decode(encodeCertificate);
            InputStream file = new ByteArrayInputStream(CertificateByte);
            cert = (X509Certificate) certificateFactory.generateCertificate(file);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return cert;
    }
}
