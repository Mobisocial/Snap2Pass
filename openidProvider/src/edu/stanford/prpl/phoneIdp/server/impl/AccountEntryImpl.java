package edu.stanford.prpl.phoneIdp.server.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import edu.stanford.prpl.phoneIdp.server.api.AccountEntry;
import edu.stanford.prpl.phoneIdp.server.api.AuthCode;
import edu.stanford.prpl.phoneIdp.server.api.Credential;

public class AccountEntryImpl extends AccountEntry {

	private AccountEntryImpl() {
		// TODO Auto-generated constructor stub
	}
	
	public AccountEntryImpl(Credential myCredential, boolean isActive)
	{
		myCredential_ = myCredential;
		isActive_ = isActive;
		outStandingAuthCodes_ = new HashMap<String, AuthCode>();
		validAuthCodes_ = new HashMap<String, AuthCode>();
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
