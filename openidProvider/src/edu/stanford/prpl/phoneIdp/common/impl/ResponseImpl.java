package edu.stanford.prpl.phoneIdp.common.impl;

import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import edu.stanford.prpl.phoneIdp.common.PhoneIdpCommon;
import edu.stanford.prpl.phoneIdp.common.api.Challenge;
import edu.stanford.prpl.phoneIdp.common.api.Response;
import edu.stanford.prpl.phoneIdp.server.api.Credential;

public class ResponseImpl extends Response {

	private ResponseImpl()
	{
		
	}
	
	public ResponseImpl(String name, String openId, Challenge c, String key)
	{
		challenge_ = c;
		name_ = name;
		openId_ = openId;
		key_ = key;
		authCode_ = challenge_.getAuthCode();
	}
	
	public ResponseImpl(Credential cred, Challenge c)
	{
		challenge_ = c;
		name_ = cred.getFriendlyName();
		openId_ = cred.getOpenId();
		key_ = cred.getSharedSecret();
		authCode_ = challenge_.getAuthCode();
	}

	//todo revisit the need of this fn
	public void extractInfo()
	{
		authCode_ = challenge_.getAuthCode();
	}
	
	@Override
	public Response createResponse() 
	{
		//todo fix this with JSON etc. 
		String plainText = getPlainText();
		try {
			signedText_ = Signature.calculateRFC2104HMAC(plainText, key_);
		} catch (SignatureException e) {
			e.printStackTrace();
		}

		return this;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		try
		{
			KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
			SecretKey key = keyGen.generateKey();
			
			Challenge c = new ChallengeImpl(null, null);
			c.createChallenge();
			System.out.println(c.toString());
			Response r = new ResponseImpl("debangsu", "http://debangsu.myopenid.com", c, new String(key.getEncoded()));
			r.createResponse();
			System.out.println(r.toString());
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
	}

}
