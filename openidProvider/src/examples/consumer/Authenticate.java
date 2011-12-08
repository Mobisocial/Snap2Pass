package examples.consumer;

import org.verisign.joid.AuthenticationRequest;
import org.verisign.joid.AuthenticationResponse;
import org.verisign.joid.Crypto;
import org.verisign.joid.DiffieHellman;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.Response;
import org.verisign.joid.consumer.Util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Properties;

/**
 * Example on how to authenticate
 */ 
public class Authenticate
{
    private Map map;
    private Map responseMap;
    
    public static void main(String[] argv) throws Exception
    {
	String id = "http://alice.example.com";
	String returnTo = "http://localhost:8080/joid_examples/echo";
	String trustRoot = "http://localhost:8080";
	String fileName = argv[0];

	new Authenticate(id, returnTo, trustRoot, fileName); 
    }

    public Authenticate(String identity, String returnTo, 
			String trustRoot, String fileName) 
	throws IOException, OpenIdException, NoSuchAlgorithmException
    {
	Properties p = new Properties();
	File f = new File(fileName);
	p.load(new FileInputStream(f));

 	String handle = p.getProperty("handle");
 	String dest = p.getProperty("_dest");

	AuthenticationRequest ar
	    = AuthenticationRequest.create(identity, returnTo, trustRoot,
					   handle);

	Response response = Util.send(ar, dest);
	System.out.println("Response="+response+"\n");

	AuthenticationResponse authr = (AuthenticationResponse) response;

 	BigInteger privKey 
	   = Crypto.convertToBigIntegerFromString(p.getProperty("privateKey"));
 	BigInteger modulus 
	    = Crypto.convertToBigIntegerFromString(p.getProperty("modulus"));
 	BigInteger serverPublic 
	    = Crypto.convertToBigIntegerFromString(p.getProperty("publicKey"));
 	byte[] encryptedKey 
	    = Crypto.convertToBytes(p.getProperty("encryptedKey"));

	DiffieHellman dh = DiffieHellman.recreate(privKey, modulus);
	Crypto crypto = new Crypto();
	crypto.setDiffieHellman(dh);
	byte[] clearKey = crypto.decryptSecret(serverPublic, encryptedKey);
	
	String signature = authr.getSignature();
	System.out.println("Server's signature: "+signature);
	
	String sigList = authr.getSignedList();
	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	System.out.println("Our signature:      "+reSigned);

    }


}
