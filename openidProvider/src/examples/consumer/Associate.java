package examples.consumer;

import org.verisign.joid.AssociationRequest;
import org.verisign.joid.AssociationResponse;
import org.verisign.joid.Crypto;
import org.verisign.joid.DiffieHellman;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.Response;
import org.verisign.joid.consumer.Util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Properties;

/**
 * Example on how to associate.
 */ 
public class Associate
{
    public static void main(String[] argv) throws Exception
    {
	String dest = "http://localhost:8080/joid_examples/server";
	new Associate(dest, argv[0]);
    }

    public Associate(String destination, String fileName) 
	throws IOException, OpenIdException
    {
	DiffieHellman dh = DiffieHellman.getDefault();
	Crypto crypto = new Crypto();
	crypto.setDiffieHellman(dh);

	AssociationRequest ar = AssociationRequest.create(crypto);

	Response response = Util.send(ar, destination);
	System.out.println("Response="+response+"\n");

 	AssociationResponse asr = (AssociationResponse) response;

	Properties props = new Properties();
	props.setProperty("handle", asr.getAssociationHandle());
	props.setProperty("publicKey", 
			  Crypto.convertToString(asr.getDhServerPublic()));
	props.setProperty("encryptedKey", 
			  Crypto.convertToString(asr.getEncryptedMacKey()));

	BigInteger privateKey = dh.getPrivateKey();
	props.setProperty("privateKey", Crypto.convertToString(privateKey));
	props.setProperty("modulus", 
		   Crypto.convertToString(DiffieHellman.DEFAULT_MODULUS));

	props.setProperty("_dest", destination);

	File f = new File(fileName);
	props.store(new FileOutputStream(f), "Association result");
	System.out.println("Results written into "+f.getCanonicalPath());

	/*
 	Crypto crypto = new Crypto();
 	dh = DiffieHellman.recreate(privateKey, p);
	crypto.setDiffieHellman(dh);
 	byte[] clearKey	= crypto.decryptSecret(asr.getDhServerPublic(), 
 					       asr.getEncryptedMacKey());
	System.out.println("Clear key: "+Crypto.convertToString(clearKey));
	*/
    }
}
