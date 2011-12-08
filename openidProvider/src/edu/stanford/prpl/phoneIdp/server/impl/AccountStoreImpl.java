/**
 * 
 */
package edu.stanford.prpl.phoneIdp.server.impl;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import edu.stanford.prpl.phoneIdp.server.api.AccountEntry;
import edu.stanford.prpl.phoneIdp.server.api.AuthCode;
import edu.stanford.prpl.phoneIdp.server.api.Credential;
import edu.stanford.prpl.phoneIdp.server.api.AccountStore;

/**
 * @author debangsu
 *
 */
public class AccountStoreImpl extends AccountStore {
	
	private static AccountStoreImpl theInstance = null;
	private static final Log log = LogFactory.getLog(AccountStoreImpl.class);
	private static Map<String, AccountEntry> accountsMap; //oid, account entry

	/**
	 * 
	 */
	private AccountStoreImpl() {
		accountsMap = new HashMap<String, AccountEntry>();
	}
	
	public synchronized static AccountStoreImpl getInstance()
	{
		if (theInstance == null)
		{
			theInstance = new AccountStoreImpl();
		}
		return theInstance;
	}

	/* (non-Javadoc)
	 * @see edu.stanford.prpl.phoneIdp.CredentialStore#activate(edu.stanford.prpl.phoneIdp.Credential)
	 */
	@Override
	public boolean activate(Credential userCred) {
		
		boolean result = false;
		
		//extract oid
		String oid = userCred.getOpenId();
		
		AccountEntry entry = accountsMap.get(oid);
		
		if (null == entry)
		{
			//create
			entry = new AccountEntryImpl(userCred, true);
			accountsMap.put(oid, entry);
			log.info("AccountStore.activate: new size is: " + accountsMap.size());
			result = true;
		}
		else
		{
			log.error("AccountStore.active: Account already exists\n" + userCred.toString());
		}
		return result;
	}
	
	@Override
	public void activateAuthCode(String openId, AuthCode acode) {

		//todo debug
		AccountEntry accountEntry = accountsMap.get(openId);
		accountEntry.getActiveAuthCodes().put(acode.getAuthCode(), acode);
		log.info("AccountStore.activateAuthCode: new size of outstanding authCodes is: " + accountEntry.getActiveAuthCodes().size());
		log.info("AccountStore.activateAuthCode: new size of valid authCodes is: " + accountEntry.getValidAuthCodes().size());
		
		return;
	}
	
	@Override
	public boolean update(String oid) {
		boolean result = false;
		AccountEntry entry = accountsMap.get(oid);
		
		if (null == entry)
		{
			log.error("CredStore.update: Account does not exist\n" + entry.toString());
			
		}
		else
		{
			//create
			entry = accountsMap.get(oid);
			entry.setActive(true);
			
			Credential c = entry.getMyCredential();
			c.setOpenId(oid);
			
			entry.setMyCredential(c);
			entry.setActiveAuthCodes(null);
			entry.setValidAuthCodes(null);
			
			accountsMap.put(oid, entry);
			result = true;
		}
		return result;
	}
	
	@Override
	public boolean update(Credential userCred)	{
		boolean result = false;
		
		//extract oid
		String oid = userCred.getOpenId();
		
		return update(oid);
	}

	/* (non-Javadoc)
	 * @see edu.stanford.prpl.phoneIdp.CredentialStore#deActivate(edu.stanford.prpl.phoneIdp.Credential)
	 */
	@Override
	public boolean deActivate(Credential userCred) {
		boolean result = false;
		
		//extract oid
		String oid = userCred.getOpenId();
		
		AccountEntry entry = accountsMap.get(oid);
		
		if (null == entry)
		{
			log.error("CredStore.deActivate: Nothing to do. Account already deactive or does not exist\n" + userCred.toString());
			result = false;
		}
		else
		{
			entry.setActive(false);
			entry.setActiveAuthCodes(null);
			entry.setValidAuthCodes(null);
			result = true;
		}
		return result;
	}
	
	@Override
	public void validateAuthCode(String openId, AuthCode acode) {

		//todo debug
		AccountEntry accountEntry = accountsMap.get(openId);
		boolean resultContains = accountEntry.getActiveAuthCodes().containsKey(acode.getAuthCode());
		AuthCode deletedAuthCode = accountEntry.getActiveAuthCodes().remove(acode.getAuthCode());
		log.info("AccountStore.deActivateAuthCode: new size of outstanding authCodes is: " + accountEntry.getActiveAuthCodes().size());
		deletedAuthCode.setValidated(true);
		accountEntry.getValidAuthCodes().put(acode.getAuthCode(), acode);
		log.info("AccountStore.deActivateAuthCode: new size of valid authCodes is: " + accountEntry.getValidAuthCodes().size());
		
		return;
	}
	
	@Override
	public boolean delete(String openId) {
		
		boolean result = false;
		
		AccountEntry entry = accountsMap.remove(openId);
		
		if (null == entry)
		{
			log.error("CredStore.deActivate: Nothing to do. Account already deleted or does not exist\n" + openId);
			result = false;
		}
		else
		{
			result = true;
			log.info("AccountStore.delete: new size is: " + accountsMap.size());
		}
		return result;
	}

	/* (non-Javadoc)
	 * @see edu.stanford.prpl.phoneIdp.CredentialStore#delete(edu.stanford.prpl.phoneIdp.Credential)
	 */
	@Override
	public boolean delete(Credential userCred) {
		boolean result = false;
		
		//extract oid
		String oid = userCred.getOpenId();
		
		return delete(oid);
	}
	
	@Override
	public void deleteOldAuthCodes()
	{
		//todo
		//on timer 10 mins go thru outstanding authcodes in cache and accountstore. delete them. 
		//on timer 30 mins go thru validated authcodes. delete them. 
	}

	/* (non-Javadoc)
	 * @see edu.stanford.prpl.phoneIdp.CredentialStore#exists(edu.stanford.prpl.phoneIdp.Credential)
	 */
	@Override
	public boolean exists(Credential userCred) {
		
		//extract oid
		String oid = userCred.getOpenId();
		
		return accountsMap.containsKey(oid);
	}

	/* (non-Javadoc)
	 * @see edu.stanford.prpl.phoneIdp.CredentialStore#get(edu.stanford.prpl.phoneIdp.Credential)
	 */
	@Override
	public AccountEntry get(Credential userCred) {
		String oid = userCred.getOpenId();
		
		return get(oid);
	}
	
	public AccountEntry get(String oid)
	{
		return accountsMap.get(oid);
	}


	/* (non-Javadoc)
	 * @see edu.stanford.prpl.phoneIdp.CredentialStore#isActive(edu.stanford.prpl.phoneIdp.Credential)
	 */
	@Override
	public boolean isActive(Credential userCred) {
		boolean result = false;
		
		String oid = userCred.getOpenId();
		
		AccountEntry entry = accountsMap.get(oid);
		
		if (null == entry)
		{
			result = false;
			log.error("CredStore.isActive: creds are not in map. \n" + userCred.toString());
		}
		else 
		{
			result = entry.isActive();
		}
		
		return result;
	}
	
	@Override
	public boolean isVerified(String oid)
	{
		boolean result = false;
		
		AccountEntry accountEntry = get(oid);
		
		if (null != accountEntry)
		{
			log.info("Oid: " + oid + ", Size of validAuthCodes: " + accountEntry.getValidAuthCodes().size());
			
			if (accountEntry.getValidAuthCodes().size() > 0)
			{
				result = true;
				log.info("Account VERIFIED");
			}
		}
		return result;
	}
	
	@Override
	public void printEntries()
	{
		for (Iterator<String> it = accountsMap.keySet().iterator(); it.hasNext();)
		{
			String entry = it.next();
			log.info("Oid: " + entry + ", " + accountsMap.get(entry).toString());
		}
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

	

	

	

}
