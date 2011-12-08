package edu.stanford.prpl.phoneIdp.client.api;

import java.io.IOException;

import sun.misc.BASE64Decoder;
import edu.stanford.prpl.phoneIdp.common.api.Challenge;
import edu.stanford.prpl.phoneIdp.common.api.Response;
import edu.stanford.prpl.phoneIdp.common.impl.ResponseImpl;
import edu.stanford.prpl.phoneIdp.server.api.Credential;

public abstract class Client {
	
	protected String sharedSecret_;
	protected String authCode_;
	protected Credential userCred_;
	protected Challenge challenge_;
	protected Response response_;
	
	public abstract void init();
	
	public abstract String registerAccount(String name, String oid);
	
	public abstract Challenge login(String name, String oid); // returns Challenge
	
	// For testing
	public void sharedSecretIs(String sharedSecret)
	{
		sharedSecret_ = sharedSecret;
	}
	
	public String authCode()
	{
		return authCode_;
	}
	
	public void authCodeIs(String authCode)
	{
		authCode_ = authCode;		
	}
	
	public void challengeIs(Challenge challenge)
	{
		challenge_ = challenge;
	}
	
	public abstract boolean sendResponse();
	
	//Based on shared HMAC class
	protected Response createResponse() {

		response_ = new ResponseImpl(userCred_, challenge_);
		response_.createResponse();
		
		return response_;
	}
	

}
