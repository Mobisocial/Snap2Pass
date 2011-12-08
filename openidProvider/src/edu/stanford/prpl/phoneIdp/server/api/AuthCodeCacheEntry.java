package edu.stanford.prpl.phoneIdp.server.api;

public abstract class AuthCodeCacheEntry {
	
	protected AuthCode authCode_;
	protected String oid_;
	
	public AuthCode getAuthCode_() {
		return authCode_;
	}
	public void setAuthCode_(AuthCode authCode) {
		authCode_ = authCode;
	}
	public String getOid_() {
		return oid_;
	}
	public void setOid_(String oid) {
		oid_ = oid;
	}	
	
	@Override
	public String toString()
	{
		return new String("authCode (key): " + authCode_.getAuthCode() + ", oid: " + getOid_());
	}

}
