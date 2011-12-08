package edu.stanford.prpl.phoneIdp.server.impl;

import java.util.Date;

import edu.stanford.prpl.phoneIdp.server.api.AuthCode;

public class AuthCodeImpl extends AuthCode {

	public AuthCodeImpl() {
		
	}
	
	public AuthCodeImpl(String authCode, Date issueDateTime, boolean validated)
	{
		authCode_ = authCode;
		issueDateTime_ = issueDateTime;
		validated_ = validated;		
	}

}
