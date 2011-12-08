package edu.stanford.prpl.phoneIdp.server.api;

import edu.stanford.prpl.phoneIdp.server.api.AuthCode;



public abstract class AccountStore {
	
	public abstract boolean activate(Credential userCred);
	
	public abstract void activateAuthCode(String openId, AuthCode acode);
	
	public abstract boolean update(Credential userCred);
	
	public abstract boolean update(String oid);
	
	public abstract boolean exists(Credential userCred);
	
	public abstract boolean isActive(Credential userCred);
	
	public abstract AccountEntry get(Credential userCred);
	
	public abstract AccountEntry get(String oid);
	
	public abstract boolean delete(String openId);
	
	public abstract boolean delete(Credential userCred);
	
	public abstract void deleteOldAuthCodes();
	
	public abstract boolean deActivate(Credential userCred);
	
	public abstract void validateAuthCode(String openId, AuthCode acode);
	
	public abstract boolean isVerified(String oid);
	
	public abstract void printEntries();
	
	
	

}
