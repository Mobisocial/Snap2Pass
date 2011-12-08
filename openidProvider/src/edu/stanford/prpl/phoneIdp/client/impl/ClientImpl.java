package edu.stanford.prpl.phoneIdp.client.impl;

import java.security.NoSuchAlgorithmException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import edu.stanford.prpl.phoneIdp.client.api.Client;
import edu.stanford.prpl.phoneIdp.common.api.Challenge;
import edu.stanford.prpl.phoneIdp.common.api.Response;
import edu.stanford.prpl.phoneIdp.common.impl.ResponseImpl;
import edu.stanford.prpl.phoneIdp.server.api.Credential;
import edu.stanford.prpl.phoneIdp.server.api.PhoneIdp;
import edu.stanford.prpl.phoneIdp.server.impl.AuthCodeCacheImpl;
import edu.stanford.prpl.phoneIdp.server.impl.CredentialImpl;
import edu.stanford.prpl.phoneIdp.server.impl.PhoneIdpImpl;
import edu.stanford.prpl.phoneIdp.server.impl.CredentialImpl.Encoding;

public class ClientImpl extends Client {
	
	private static final Log log = LogFactory.getLog(ClientImpl.class);
	
	PhoneIdp phoneIdp_;


	@Override
	public void init() {
		phoneIdp_ = PhoneIdpImpl.getInstance();

	}

	@Override
	public Challenge login(String name, String oid) {
		
		try {
			userCred_ = new CredentialImpl(name, oid, sharedSecret_, true, Encoding.BASE64);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		challenge_ = phoneIdp_.createChallenge(userCred_);

		return challenge_;
	}

	@Override
	public String registerAccount(String name, String oid) {
		
		Credential cred = phoneIdp_.createAccount(name, oid);
		sharedSecret_ = cred.getSharedSecret(); //base64 encoded
		return sharedSecret_;
	}

	@Override
	public boolean sendResponse() {
		boolean result = false;
		createResponse();
		result = phoneIdp_.verifyResponse(response_.getSignedText_());
		return result;
	}
	
	public void testLoLevel()
	{
		String name = "d1";
		String oid = "http://localhost:8080/joid/users/d1";
		String sharedSecret = registerAccount(name, oid);
		Challenge challenge = login(name, oid);
		boolean result = sendResponse();
		
		log.info("Client: Result of Lo Level verify is: " + result);	
	}
	
	public void testHiLevel()
	{
		String name = "d2";
		String oid = "http://localhost:8080/joid/users/d2";
		PhoneIdp phoneIdp = PhoneIdpImpl.getInstance();
		userCred_ = phoneIdp.createAccount(name, oid);
		String sharedSecret = userCred_.getSharedSecret();
		
		challenge_ = phoneIdp.createChallenge(oid);
		boolean verifyResult1 = phoneIdp_.isVerified(oid, challenge_.getAuthCode());
		log.info("Pre response: isVerified expected result: false, actual result: " + verifyResult1);
		
		boolean result = sendResponse();
		boolean verifyResult2 = phoneIdp_.isVerified(oid, challenge_.getAuthCode());
		log.info("Pre response: isVerified expected result: true, actual result: " + verifyResult2);
		
		log.info("Client: Result of Hi Level verify is: " + result);	
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		log.info("Client: Start");
		
		Client client = new ClientImpl();
		client.init();
		((ClientImpl) client).testLoLevel();
		
		
		Client client2 = new ClientImpl();
		client2.init();	
		((ClientImpl) client2).testHiLevel();
		
	}

}
