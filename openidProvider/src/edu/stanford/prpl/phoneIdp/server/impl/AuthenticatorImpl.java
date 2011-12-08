package edu.stanford.prpl.phoneIdp.server.impl;

import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServlet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import edu.stanford.prpl.phoneIdp.common.api.Challenge;
import edu.stanford.prpl.phoneIdp.common.api.Response;
import edu.stanford.prpl.phoneIdp.common.impl.ChallengeImpl;
import edu.stanford.prpl.phoneIdp.common.impl.ResponseImpl;
import edu.stanford.prpl.phoneIdp.common.impl.Signature;
import edu.stanford.prpl.phoneIdp.server.api.AccountEntry;
import edu.stanford.prpl.phoneIdp.server.api.AccountStore;
import edu.stanford.prpl.phoneIdp.server.api.AuthCode;
import edu.stanford.prpl.phoneIdp.server.api.AuthCodeCache;
import edu.stanford.prpl.phoneIdp.server.api.AuthCodeCacheEntry;
import edu.stanford.prpl.phoneIdp.server.api.Authenticator;
import edu.stanford.prpl.phoneIdp.server.api.Credential;

public class AuthenticatorImpl extends Authenticator {
	
	private static final Log log = LogFactory.getLog(AuthenticatorImpl.class);
	
	public AuthenticatorImpl()	{
		
		// for testing
		accountStore_ = AccountStoreImpl.getInstance();
		authCodeCache_ = AuthCodeCacheImpl.getInstance();
		
	}
	
	@Override
	public Challenge generateChallenge(Credential cred) {

		//todo pass in http request so that endpoint can be calculated correctly. 
		Challenge c = new ChallengeImpl(null, null);
		c.createChallenge();
		
		AuthCode acode = new AuthCodeImpl(c.getAuthCode(), new Date(), false);
		
		//store in accountsstore activeauthcodes
		accountStore_.activateAuthCode(cred.getOpenId(), acode);
		//store in authcode cache for reverse lookup
		authCodeCache_.add(c.getAuthCode(), cred.getOpenId());		
		
		return c;
	}


	public boolean verifyResponse(String signedText)
	{
		boolean result = false;
		
		//try against all outstanding open authcodes
		
		for (Iterator<String> it = authCodeCache_.getAuthCodeOidMap().keySet().iterator(); 
			it.hasNext();)
		{
			AuthCodeCacheEntry cacheEntry = authCodeCache_.get(it.next());
			Credential userCred_ = accountStore_.get(cacheEntry.getOid_()).getMyCredential();
			
			//Look up AccountsStore with OID. Get shared secret
			String sharedSecret = userCred_.getSharedSecret();
			
			//Create response object and plain text
			//decoding the encoded authcode
			
			Challenge expectedChallenge = new ChallengeImpl(null, cacheEntry.getAuthCode_().getAuthCode());
			expectedChallenge.setEndPointURL();
			
			Response expectedResponse = new ResponseImpl(userCred_, expectedChallenge);
			String expectedPlainText = expectedResponse.getPlainText();
			
			//Do signing.
			String expectedSignedText = null;
			try
			{
				expectedSignedText = Signature.calculateRFC2104HMAC(expectedPlainText, sharedSecret);
			}
			catch (SignatureException e)
			{
				e.printStackTrace();
			}
			
			log.info("Authcodecache Entry: " + cacheEntry.getAuthCode_().getAuthCode() + ", expectedPlainText: " + expectedPlainText + 
					", expectedSignedText: " + expectedSignedText + ", actualSignedText: " + signedText);
			
			
			//Match against resp. 
			result = signedText.equals(expectedSignedText);
			
			if (result)
			{
				//Do housekeeping
				authCodeCache_.deactivate(cacheEntry.getAuthCode_().getAuthCode());
				accountStore_.validateAuthCode(userCred_.getOpenId(), cacheEntry.getAuthCode_());
				break;
			}			
			
			authCodeCache_.printEntries();
		}
		
		return result;
	}
	
	@Override
	public boolean verifyResponse(Response resp) {
		//Assumption: have been able to construct a response object 
		//with plaintext authCode
		
		boolean result = false;
		
		
		//try against all outstanding open authcodes
		
		for (Iterator<String> it = authCodeCache_.getAuthCodeOidMap().keySet().iterator(); 
			it.hasNext();)
		{
			AuthCodeCacheEntry cacheEntry = authCodeCache_.get(it.next());

			
			//Lookup AccountsStore with OID. Get shared secret
			String sharedSecret = accountStore_.get(cacheEntry.getOid_()).getMyCredential().getSharedSecret();
			
			//Do signing.
			String expectedSignedText = null;
			try
			{
				expectedSignedText = Signature.calculateRFC2104HMAC(cacheEntry.getAuthCode_().getAuthCode(), sharedSecret);
			}
			catch (SignatureException e)
			{
				e.printStackTrace();
			}
			
			
			//Match against resp. 
			result = resp.getSignedText_().equals(expectedSignedText);
			
			if (result)
			{
				break;
			}			
		}
		
		authCodeCache_.printEntries();
		return result;
	}

}
