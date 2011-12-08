package edu.stanford.prpl.phoneIdp.server.impl;

import java.io.IOException;
import java.io.Serializable;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import sun.misc.BASE64Decoder;

import edu.stanford.prpl.phoneIdp.server.api.Credential;

public class CredentialImpl extends Credential implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6932186302002685204L;
	protected boolean encoded = false;
	public enum Encoding { BASE64, NONE; }

	private CredentialImpl() {
	}
	
	public CredentialImpl(String name, String openId, byte[] sharedSecret, 
			boolean isEncoded, Encoding encoding) throws NoSuchAlgorithmException
	{
		this(name, openId, new String(sharedSecret), isEncoded, encoding);
	}
	
	public CredentialImpl(String name, String openId, String sharedSecret, 
			boolean isEncoded, Encoding encoding) throws NoSuchAlgorithmException
	{
		friendlyName_ = name;
		openId_ = openId;

		if ((isEncoded) && (encoding == Encoding.BASE64))
		{
			setSharedSecret(sharedSecret);
		}
		else if (isEncoded)
		{
			throw new NoSuchAlgorithmException("Encoding not supported yet");
		}
		else
		{
			//We received unencoded sharedSecret
			sharedSecret_ = sharedSecret.getBytes();
		}
		
	}
	
	public CredentialImpl(String name, String openId, byte[] sharedSecret) throws NoSuchAlgorithmException
	{
		this(name, openId, sharedSecret, false, Encoding.NONE);
	}
	
	/**
	 * @param args
	 * @throws NoSuchAlgorithmException 
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException {
		
		String name = "debangsu";
		String openId = "http://debangsu.myopenid.com";
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
		SecretKey key = keyGen.generateKey();
		byte[] sharedSecret = key.getEncoded();
		System.out.println(key.getFormat());
		System.out.println(key.getAlgorithm());
		
		
		Credential cred = new CredentialImpl(name, openId, sharedSecret);
		System.out.println(cred.toString());
	
	}

}
