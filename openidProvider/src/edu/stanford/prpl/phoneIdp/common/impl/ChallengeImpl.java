package edu.stanford.prpl.phoneIdp.common.impl;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import edu.stanford.prpl.phoneIdp.common.PhoneIdpCommon;
import edu.stanford.prpl.phoneIdp.common.api.Challenge;

public class ChallengeImpl extends Challenge {
	
	
	
	//todo make this class have static methods
	private ChallengeImpl()
	{
		
	}
	
	public ChallengeImpl(HttpServletRequest request, String authCode)
	{
		if (null != request)
		{
			request_ = request;
		}
		if (null != authCode)
		{
			setAuthCode(authCode);
		}
	}
	
	@Override
	//Generate authcode, package it up
	public Challenge createChallenge() {
		
		//Generate authcode
		// Create a secure random number generator
		try
		{
			//dsg note: here, secure random may not be needed. Just needs to be unique.
			//remove if it slows things down a lot.
			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
			
			//Get 128 random bits
			byte[] bytes = new byte[authCodeLength/8];
			sr.nextBytes(bytes);
			
			authCode_ = new String(bytes);
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}

		
		setEndPointURL();
		
		return this;
	}
	
	@Override
	public String getAuthCode()
	{
		return new BASE64Encoder().encode(authCode_.getBytes());
	}
	
	@Override
	public void setAuthCode(String authCode)
	{
		try {
			authCode_ = new String(new BASE64Decoder().decodeBuffer(authCode));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Override
	public void setEndPointURL()
	{
		//Set endPointURL
		try
		{
			//URI tempURI = new URI(request_.getRequestURL().toString());
			URI tempURI = new URI(PhoneIdpCommon.LISTEN_END_PT_URL, false);
			tempURI.setQuery("mode=" + PhoneIdpCommon.VERIFY_RESPONSE_MODE);
			listenEndPtURL_ = tempURI.toString();
		}
		catch (URIException e)
		{
			e.printStackTrace();
		}
		
	}

	@Override	
	public String toString()
	{
		String retVal = "Challenge: authCode = " + getAuthCode() + " listenEndpointURL: " + listenEndPtURL_;
		return retVal;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Challenge c = new ChallengeImpl(null, null);
		c = c.createChallenge();
		System.out.println(c.toString());

	}

}
