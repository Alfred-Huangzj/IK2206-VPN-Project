/**
 * Client side of the handshake.
 */

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.Socket;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class ClientHandshake {
    private static Arguments arguments;

    /*
     * The parameters below should be learned by the client
     * through the handshake protocol. 
     */
    
    /* Session host/port  */
    public static String sessionHost = "localhost";
    public static int sessionPort = 12345;

    /* String flag indicate message type */
    public String flag;

    /* Security parameters key/iv should also go here. Fill in! */
    public byte[] sessionKey;
    public byte[] sessionIV;

    /* Send ClientHello Message to Server */
    public void ClientHello(Socket handshakeSocket,String usercer) throws CertificateException, IOException {
        flag = "ClientHello";
        HandshakeMessage ClientHandshakeMessage = new HandshakeMessage();
        X509Certificate ClientCert = Certificate.getCertificate(usercer);

        ClientHandshakeMessage.putParameter("MessageType","ClientHello");
        ClientHandshakeMessage.putParameter("Certificate",Certificate.encodeCertificate(ClientCert));
        ClientHandshakeMessage.send(handshakeSocket);
        Logger.log(flag + " send successfully.");
    }
    /**
     *  Get Server Certificate from ServerHello Message
     *  Verify ServerHello message from Server
     */
    public void ServerHelloVerify(Socket handshakeSocket,String cacert) throws IOException {
        flag = "ServerHello";
        HandshakeMessage FromServer = new HandshakeMessage();
        FromServer.recv(handshakeSocket);
        if(FromServer.getParameter("MessageType").equals("ServerHello")){
            try {
                X509Certificate ServerCertificate = Certificate.decodeCertificate(FromServer.getParameter("Certificate"));
                Certificate.verifyCertificate(flag,cacert,ServerCertificate);
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
    /**
     * Send ClientForwrd message to Server while the ServerHello has been successfully verified
     * ClientForward message contains TargetHost and TargetPort
     */
    public void ClientForward(Socket handshakeSocket,String TargetHost,String TargetPort) throws IOException {
        flag = "ClientForward";

        HandshakeMessage ClientForwardMessage = new HandshakeMessage();
        ClientForwardMessage.putParameter("MessageType", "Forward");
        ClientForwardMessage.putParameter("TargetHost", TargetHost);
        ClientForwardMessage.putParameter("TargetPort", TargetPort);
        ClientForwardMessage.send(handshakeSocket);
        Logger.log(flag + " send successfully.");
    }
    /**
     * Get Session key and IV form Server
     * SessionKey: An AES key encrypted with the client's public key, and then encoded as a string
     * SessionIV: An initialisation vector for AES in CTR mode, encrypted with the client's public
     * key, and then encoded as a string
     * SessionHost: Name of the host to which ForwardClient should connect to establish the session (String)
     * SessionPort: TCP port number (as a string!) to which ForwardClient should connect to establish
     * the session
     */
    public void ClienSessionRecv(Socket handshakeSocket,String ClientPrivateKeyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        HandshakeMessage RecvSession = new HandshakeMessage();
        RecvSession.recv(handshakeSocket);
        if (RecvSession.getParameter("MessageType").equals("Session")){
            PrivateKey ClientPrivatyKey = HandshakeDecrypt.getPrivateKey(ClientPrivateKeyFile);
            sessionKey = HandshakeDecrypt.HandshakeDecrypt(Base64.getDecoder().decode(RecvSession.getParameter("SessionKey")), ClientPrivatyKey);
            sessionIV = HandshakeDecrypt.HandshakeDecrypt(Base64.getDecoder().decode(RecvSession.getParameter("SessionIV")), ClientPrivatyKey);
            sessionHost = RecvSession.getParameter("SessionHost");
            sessionPort = Integer.parseInt(RecvSession.getParameter("SessionPort"));
            Logger.log("Session message received.");
            Logger.log("Client handshake finished.");
        }
        else {
            Logger.log("Session message type error.");
            handshakeSocket.close();
        }
    }
    public byte[] getSessionKey(){
        return sessionKey;
    }

    public byte[] getSessionIV(){
        return sessionIV;
    }
    /**
     * Run client handshake protocol on a handshake socket. 
     * Here, we do nothing, for now.
     */ 
    public ClientHandshake(Socket handshakeSocket,String targethost,String targetport,String cacert,String usercert,String ClientPrivateKeyFile) throws IOException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, CertificateException {
        ClientHello(handshakeSocket, usercert);
        ServerHelloVerify(handshakeSocket, cacert);
        ClientForward(handshakeSocket, targethost, targetport);
        ClienSessionRecv(handshakeSocket, ClientPrivateKeyFile);
    }

}
