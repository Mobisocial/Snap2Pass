package edu.stanford.prpl.phoneIdp.server.impl;

import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import edu.stanford.prpl.phoneIdp.common.PhoneIdpCommon;
import edu.stanford.prpl.phoneIdp.server.api.AccountEntry;
import edu.stanford.prpl.phoneIdp.server.api.AccountStore;
import edu.stanford.prpl.phoneIdp.server.api.AuthCode;
import edu.stanford.prpl.phoneIdp.server.api.AuthCodeCache;
import edu.stanford.prpl.phoneIdp.server.api.AuthCodeCacheEntry;

public class AuthCodeCacheImpl extends AuthCodeCache {
	
	private static final Log log = LogFactory.getLog(AuthCodeCacheImpl.class);
	
	private static AuthCodeCacheImpl theInstance = null;

	private AuthCodeCacheImpl()
	{
		authCodeOidMap = new HashMap<String, AuthCodeCacheEntry>();
		accountStore_ = AccountStoreImpl.getInstance();
	}
	
	public synchronized static AuthCodeCacheImpl getInstance()
	{
		if (theInstance == null)
		{
			theInstance = new AuthCodeCacheImpl();		
		}
		return theInstance;
	}
	
	
	@Override
	public boolean add(String authCode, String oid) {
		boolean result = false;
		
		AuthCodeCacheEntry entry = new AuthCodeCacheEntryImpl(authCode, oid);
		authCodeOidMap.put(authCode, entry);
		result = true;
		
		log.info("AuthCodeCacheImpl.add: New size is: " + authCodeOidMap.size());
		return result;
	}
	
	@Override
	public void deactivateUsed()
	{
		//todo. may not need it
		
	}
	
	public void deactivate(String authCode)
	{
		AuthCodeCacheEntry cacheEntry = authCodeOidMap.get(authCode);
		authCodeOidMap.remove(authCode);
		log.info("AuthCodeCacheImpl.deactivate: New size is: " + authCodeOidMap.size());
		
	}

	@Override
	public void deactivateExpired() {

		//Step thru authcodes, delete the ones that are order
		Iterator<String> it = authCodeOidMap.keySet().iterator();
		
		while (it.hasNext())
		{
			String authCode = it.next();
			AuthCodeCacheEntry cacheEntry = authCodeOidMap.get(authCode);
			Date now = new Date();
			AuthCode acode = cacheEntry.getAuthCode_();
			String oid = cacheEntry.getOid_();
			Date entryDate = acode.getIssueDateTime();
			Long elapsed = now.getTime() - entryDate.getTime();
			
			if (elapsed > PhoneIdpCommon.AUTHCODE_VALID_DURATION_MS)
			{
				//Delete overhead elsewhere
				
				//Update the credential
				if (accountStore_ != null)
				{
					accountStore_.validateAuthCode(oid, acode);
				}
				authCodeOidMap.remove(authCode);
				log.info("AuthCodeCacheImpl.deactivateExpired: New size is: " + authCodeOidMap.size());
			}
		}
	}
	
	@Override
	public AuthCodeCacheEntry get(String authCode) {
		return authCodeOidMap.get(authCode);
	}

	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

	@Override
	public void printEntries() {

		for (Iterator<String> it = authCodeOidMap.keySet().iterator(); it.hasNext();)
		{
			String entry = it.next();
			log.info("AuthCodeCache: AuthCode" + entry + ", " + authCodeOidMap.get(entry).toString());
		}
		
	}

	

}
