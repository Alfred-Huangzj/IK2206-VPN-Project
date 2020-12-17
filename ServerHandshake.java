/**
 * Server side of the handshake.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol. 
     */
    
    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;    

    /* The final destination -- simulate handshake with constants */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    /* String flag indicate message type */
    public String flag;

    /* Security parameters key/iv should also go here. Fill in! */
    public byte[] sessionKey;
    public byte[] sessionIV;

    /* Certificate receive from Client*/
    public X509Certificate ClientCertificate;

    /* Verify ClientHello message */
    public void ClientHelloVerify(Socket handshakeSocket,String cacert) throws IOException {
        flag = "ClientHello";
        HandshakeMessage FromClient = new HandshakeMessage();
        FromClient.recv(handshakeSocket);
        if (FromClient.getParameter("MessageType").equals("ClientHello")){
            try {
                ClientCertificate = Certificate.decodeCertificate(FromClient.getParameter("Certificate"));
                Certificate.verifyCertificate(flag,cacert,ClientCertificate);
            } catch (Exception e) {
                Logger.log(flag + " verify failed.");
                handshakeSocket.close();
            }
        }
        else{
            Logger.log("Message type error.");
            handshakeSocket.close();
        }
    }
    /* Send ServerHello Message to Server */
    public void ServerHello(Socket handshakeSocket,String usercert) throws CertificateException, IOException {
        flag = "ServerHello";
        HandshakeMessage ClientHandshakeMessage = new HandshakeMessage();
        X509Certificate ClientCert = Certificate.getCertificate(usercert);

        ClientHandshakeMessage.putParameter("MessageType","ServerHello");
        ClientHandshakeMessage.putParameter("Certificate",Certificate.encodeCertificate(ClientCert));
        ClientHandshakeMessage.send(handshakeSocket);
        Logger.log(flag + " send successfully.");
    }
    /* Verify ClientForward message */
    public void ClientForwardVerify(Socket handshakeSocket) throws IOException {
        HandshakeMessage ClientForward = new HandshakeMessage();
        ClientForward.recv(handshakeSocket);
        if(ClientForward.getParameter("MessageType").equals("Forward")){
            targetHost = ClientForward.getParameter("TargetHost");
            targetPort = Integer.parseInt(ClientForward.getParameter("TargetPort"));
            Logger.log("Server forward verify succeed.");
        }
        else{
            Logger.log("Forward message type error.");
            handshakeSocket.close();
        }
    }
    /**
     * Send Session Message to Client
     * SessionPort: 12345
     * Session encrypted with client's public key
     */
    public void ServerSessionSend(Socket handshakeSocket) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IOException {
        flag = "ServerSession";

        HandshakeMessage ServerSessionMessage = new HandshakeMessage();
        ServerSessionMessage.putParameter("MessageType","Session");
        /* Generate Security Number with keylength 128 bits */
        SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
        sessionKey = sessionEncrypter.GetSessionKey();
        sessionIV = sessionEncrypter.GetIV();
        /* Get client's public key from client certificate */
        PublicKey ClientPublicKey = ClientCertificate.getPublicKey();
        byte[] EncryptedKey = HandshakeEncrypt.HandshakeEncrypt(sessionKey,ClientPublicKey);
        byte[] EncrypteIV = HandshakeEncrypt.HandshakeEncrypt(sessionIV,ClientPublicKey);
        ServerSessionMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(EncryptedKey));
        ServerSessionMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(EncrypteIV));
        ServerSessionMessage.putParameter("SessionHost",sessionHost);
        ServerSessionMessage.putParameter("SessionPort",String.valueOf(sessionPort));
        ServerSessionMessage.send(handshakeSocket);
        Logger.log("Session created.");
        Logger.log(flag + " send successfully!");
        Logger.log("Server handshake finshed.");
    }
    public byte[] getSessionKey(){
        return sessionKey;
    }

    public byte[] getSessionIV(){
        return sessionIV;
    }
    /**
     * Run server handshake protocol on a handshake socket. 
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */ 
    public ServerHandshake(Socket handshakeSocket,String cacert,String usercert) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        sessionSocket = new ServerSocket(12345);
        sessionHost = sessionSocket.getInetAddress().getHostName();
        sessionPort = sessionSocket.getLocalPort();
        ClientHelloVerify(handshakeSocket,cacert);
        ServerHello(handshakeSocket,usercert);
        ClientForwardVerify(handshakeSocket);
        ServerSessionSend(handshakeSocket);
    }
}
