package edu.stanford.prpl.phoneIdp.common.api;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;

import edu.stanford.prpl.phoneIdp.common.PhoneIdpCommon;

public abstract class Challenge {
	
	protected String listenEndPtURL_;
	protected String authCode_;
	protected int authCodeLength = 128; //bits
	protected HttpServletRequest request_;
	
	public abstract Challenge createChallenge();
	
	public abstract String getAuthCode(); // returns base64 encoded string
	public abstract void setAuthCode(String authCode); //argument base 64 encoded authcode
	
	public abstract void setEndPointURL();

}
