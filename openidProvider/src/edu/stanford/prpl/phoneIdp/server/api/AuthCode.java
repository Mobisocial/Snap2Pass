package edu.stanford.prpl.phoneIdp.server.api;

import java.util.Date;

public abstract class AuthCode {
	protected String authCode_;
	protected Date issueDateTime_;
	protected boolean validated_;

	public void setAuthCode(String authCode) {
		this.authCode_ = authCode;
	}

	public String getAuthCode() {
		return authCode_;
	}

	public void setIssueDateTime(Date issueDateTime) {
		this.issueDateTime_ = issueDateTime;
	}

	public Date getIssueDateTime() {
		return issueDateTime_;
	}

	public void setValidated(boolean validated) {
		this.validated_ = validated;
	}

	public boolean isValidated() {
		return validated_;
	}
	
	@Override
	public String toString()
	{
		String result = "Authcode: " + authCode_ + ", IssueDateTime: " + issueDateTime_.toString() + ", validated: " + validated_;
		return result;
	}

}
