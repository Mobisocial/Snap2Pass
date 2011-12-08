package edu.stanford.prpl.phoneIdp.server.api;

import java.util.Map;

import edu.stanford.prpl.phoneIdp.common.api.Challenge;

public abstract class PhoneIdp {
	protected Registrar pIdpRegistrar_;
	protected Authenticator pIdpAuthenticator_;
	protected AuthCodeCache pIdpAuthCodeCache_;
	protected AccountStore pIdpAccountStore_;
	
	
	public abstract Credential createAccount(String name, String openId);
	
	public abstract Credential getAccount(String openId);
	
	public abstract boolean deleteAccount(String openId);
	
	public abstract Challenge createChallenge(String oid);
	
	//for testing
	public abstract Challenge createChallenge(Credential userCred);
	
	public abstract boolean verifyResponse(String signedText);
	
	public abstract boolean isVerified(String oid, String authcode);
	
	public abstract boolean isAccountVerified(String oid);
	

}
