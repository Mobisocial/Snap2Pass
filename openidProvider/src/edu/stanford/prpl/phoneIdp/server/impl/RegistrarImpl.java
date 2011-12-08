package edu.stanford.prpl.phoneIdp.server.impl;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import edu.stanford.prpl.phoneIdp.common.api.Challenge;
import edu.stanford.prpl.phoneIdp.common.api.Response;
import edu.stanford.prpl.phoneIdp.common.impl.ChallengeImpl;
import edu.stanford.prpl.phoneIdp.common.impl.ResponseImpl;
import edu.stanford.prpl.phoneIdp.server.api.AccountStore;
import edu.stanford.prpl.phoneIdp.server.api.Credential;
import edu.stanford.prpl.phoneIdp.server.api.Registrar;
import edu.stanford.prpl.phoneIdp.server.impl.CredentialImpl.Encoding;
import sun.misc.BASE64Encoder;

public class RegistrarImpl extends Registrar {
	
	private static final Log log = LogFactory.getLog(RegistrarImpl.class);

	public RegistrarImpl()
	{
		accountStore_ = AccountStoreImpl.getInstance();
	}
	
	@Override
	public Credential createAccount(String name, String oid) {
		
		byte[] sharedSecret = null;
		
		try
		{
			KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
			SecretKey key = keyGen.generateKey();
			byte[] tempKey = key.getEncoded();
			
			sharedSecret = new byte[55];
			
			for (int i=0; i< sharedSecret.length; ++i)
			{
				sharedSecret[i] = tempKey[i];
			}
			
			log.info("Shared secret format: " + key.getFormat());
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		
		Credential c = null;
		
		try
		{
			c = new CredentialImpl(name, oid, sharedSecret, false, Encoding.NONE);
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		
		if (accountStore_.activate(c))
		{
			return c;
		}
		else
		{
			return null;
		}
	}
	
	@Override
	public boolean updateAccount(String oid) {
		
		return accountStore_.update(oid);
		
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		RegistrarImpl regImpl = new RegistrarImpl();
		String name = "d1";
		String oid = "http://localhost:8080/joid/user/d1";
		Credential cred = regImpl.createAccount(name, oid);
		System.out.println("SharedSecret: " + cred.getSharedSecret());

	}

	@Override
	public boolean deleteAccount(String oid) {
		
		return accountStore_.delete(oid);
	}

	

}
