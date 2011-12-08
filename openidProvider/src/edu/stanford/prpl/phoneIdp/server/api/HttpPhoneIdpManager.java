package edu.stanford.prpl.phoneIdp.server.api;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class HttpPhoneIdpManager {
	
	
	protected PhoneIdp phoneIdpImpl_;
	
	public abstract void createAccount(HttpServletRequest req, HttpServletResponse resp);
	
	public abstract void getUpdateAccountDetails(HttpServletRequest req, HttpServletResponse resp);
	
	public abstract boolean deleteAccount(HttpServletRequest req, HttpServletResponse resp);
	
	public abstract void createChallenge(HttpServletRequest req, HttpServletResponse resp);
	
	public abstract boolean verifyResponse(HttpServletRequest req, HttpServletResponse resp);
	
	public abstract boolean isVerified(HttpServletRequest req, HttpServletResponse resp);
	
	public abstract boolean isAccountValid(HttpServletRequest req, HttpServletResponse resp);
	
	
}
