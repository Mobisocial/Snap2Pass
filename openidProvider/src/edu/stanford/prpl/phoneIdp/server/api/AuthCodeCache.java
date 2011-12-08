package edu.stanford.prpl.phoneIdp.server.api;

import java.util.HashMap;

public abstract class AuthCodeCache {
	
	protected AccountStore accountStore_;
	protected HashMap<String, AuthCodeCacheEntry> authCodeOidMap; 
		//authCode (key), oid's. Should it be credentials.
	
	public HashMap<String, AuthCodeCacheEntry> getAuthCodeOidMap() {
		return authCodeOidMap;
	}

	public abstract boolean add(String authcode, String oid);
	
	public abstract AuthCodeCacheEntry get(String authcode);
	
	public abstract void deactivateUsed();
	
	public abstract void deactivate(String authcode);
	
	public abstract void deactivateExpired();
	
	//For testing
	public abstract void printEntries();
	
}
