package edu.stanford.prpl.phoneIdp.server.impl;

import java.util.Date;

import junit.framework.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import edu.stanford.prpl.phoneIdp.common.PhoneIdpCommon;
import edu.stanford.prpl.phoneIdp.common.api.Challenge;
import edu.stanford.prpl.phoneIdp.server.api.AccountEntry;
import edu.stanford.prpl.phoneIdp.server.api.AuthCode;
import edu.stanford.prpl.phoneIdp.server.api.Credential;
import edu.stanford.prpl.phoneIdp.server.api.PhoneIdp;

public class PhoneIdpImpl extends PhoneIdp {
	
	private static final Log log = LogFactory.getLog(PhoneIdpImpl.class);
	
	private PhoneIdpImpl()
	{
		pIdpAccountStore_ = AccountStoreImpl.getInstance();
		pIdpAuthCodeCache_ = AuthCodeCacheImpl.getInstance();
		pIdpRegistrar_ = new RegistrarImpl();
		pIdpAuthenticator_ = new AuthenticatorImpl();
	}
	
	private static PhoneIdpImpl theInstance;
	
	public static PhoneIdpImpl getInstance()
	{
		if (theInstance == null)
		{
			theInstance = new PhoneIdpImpl();
		}
		return theInstance;
	}
	
	//singleton todo
	//init shared state - cred store
	//init Registrar
	//init Authenticator


	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

	@Override
	public Credential createAccount(String name, String openId) {
		log.info("openId: " + openId);
		log.info("name: " + name);
		Credential userCred = pIdpRegistrar_.createAccount(name, openId);
		log.info("PhoneIdpImpl.createAccount: Cred: " + userCred.toString());
		
		return userCred;
	}
	
	@Override
	public Credential getAccount(String openId) {
		log.info("openId: " + openId);
		AccountEntry accountEntry = pIdpAccountStore_.get(openId);
		
		if (null != accountEntry)
		{
			log.info("Found account entry: " + accountEntry.toString());
			return accountEntry.getMyCredential();
		}
		log.info("Did not find account entry");
		return null;
	}
	
	@Override
	public boolean deleteAccount(String openId) {
		boolean result = pIdpRegistrar_.deleteAccount(openId);
		log.info("PhoneIdpImpl.deleteAccount: OpenId: " + openId + ", Result: " + result);
		return result;
	}
	
	@Override
	public Challenge createChallenge(String oid)
	{
		log.info("createChallenge: OpenId: " + oid);
		Assert.assertNotNull(pIdpAccountStore_);
		AccountEntry accountEntry = pIdpAccountStore_.get(oid);

		//DEBUG
		if (null == accountEntry)
		{
			log.error("CreateChallenge called for inactive user");
			pIdpAccountStore_.printEntries();
		}
		
		Credential userCred = accountEntry.getMyCredential();
		return createChallenge(userCred);
	}

	@Override
	public Challenge createChallenge(Credential userCred) {

		Challenge challenge = pIdpAuthenticator_.generateChallenge(userCred);
		log.info("PhoneIdpImpl.createChallenge: Challenge: " + challenge.toString());
		return challenge;
	}

	

	@Override
	public boolean verifyResponse(String signedText) {
		boolean result = pIdpAuthenticator_.verifyResponse(signedText);
		log.info("PhoneIdpImpl.verifyResponse: SignedText: " + signedText + ", Result: " + result);
		return result;
	}

	@Override
	public boolean isVerified(String oid, String authcode) {

		boolean result = false;
		log.info("isVerified: oid: " + oid + ", authcode: "+ authcode);
		AccountEntry accountEntry = pIdpAccountStore_.get(oid);
		AuthCode acode = accountEntry.getValidAuthCodes().get(authcode);
		
		if (null != acode)
		{
			Date now = new Date();
			long elapsed = now.getTime() - acode.getIssueDateTime().getTime();
			log.info("Authcode time: " + acode.getIssueDateTime().toString());
			log.info("Now: " + now.toString());
			log.info("Elapsed time: " + elapsed);
			
			if (elapsed < PhoneIdpCommon.AUTHCODE_VALID_DURATION_MS)
			{
				log.info("isVerified: TRUE");
				result = true;
			}
			else
			{
				log.info("isVerified: FALSE");
			}
		}
		else
		{
			log.info("isVerified: FALSE. Not found in validAuthCodes");
		}
		return result;
	}

	
	public boolean isAccountVerified(String oid)
	{
		log.info("isAccountVerified: oid: " + oid);
		
		return pIdpAccountStore_.isVerified(oid);
	}
	

}
