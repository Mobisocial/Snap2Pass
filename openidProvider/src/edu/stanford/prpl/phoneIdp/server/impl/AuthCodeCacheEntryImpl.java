package edu.stanford.prpl.phoneIdp.server.impl;

import java.util.Date;

import edu.stanford.prpl.phoneIdp.server.api.AuthCodeCacheEntry;

public class AuthCodeCacheEntryImpl extends AuthCodeCacheEntry {
	
	public AuthCodeCacheEntryImpl(String authCode, String oid)
	{
		authCode_ = new AuthCodeImpl(authCode, new Date(), false);
		oid_ = oid;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
