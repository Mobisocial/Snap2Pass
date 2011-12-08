package edu.stanford.prpl.phoneIdp.client.impl;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.verisign.joid.server.OpenIdServlet;

import edu.stanford.prpl.phoneIdp.client.api.Client;
import edu.stanford.prpl.phoneIdp.common.PhoneIdpCommon;
import edu.stanford.prpl.phoneIdp.common.api.Challenge;
import edu.stanford.prpl.phoneIdp.common.api.Response;
import edu.stanford.prpl.phoneIdp.common.impl.ChallengeImpl;
import edu.stanford.prpl.phoneIdp.server.impl.CredentialImpl;
import edu.stanford.prpl.phoneIdp.server.impl.CredentialImpl.Encoding;

public class HttpClientImpl extends Client {
	
	protected static final Log log = LogFactory.getLog(HttpClientImpl.class);
	protected HttpClient webClient_;
	protected GetMethod getMethod_;
	protected PostMethod postMethod_;

	public HttpClientImpl() {
			
	}

	@Override
	public void init() {
		webClient_ = new HttpClient();
		getMethod_ = new GetMethod();
		// Provide custom retry handler is necessary
		getMethod_.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, 
	    		new DefaultHttpMethodRetryHandler(3, false));
		
		postMethod_ = new PostMethod();
		postMethod_ = new PostMethod();
		postMethod_.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, 
				new DefaultHttpMethodRetryHandler(3, false));

	}
	
	protected void finalize()
	{
		getMethod_.releaseConnection();
		postMethod_.releaseConnection();
	}

	@Override
	public Challenge login(String name, String oid) {
		
		try {
			userCred_ = new CredentialImpl(name, oid, sharedSecret_, true, Encoding.BASE64);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		// TODO Auto-generated method stub
		// todo send createChallenge request via HTTP post
		
		return null;
	}

	@Override
	public String registerAccount(String name, String oid) {
		
		URI uri;
		try {
			uri = new URI(PhoneIdpCommon.BASE_URL + PhoneIdpCommon.RP_PAGE, false);
			postMethod_.setURI(uri);
			postMethod_.addParameter("signin", "true");
			postMethod_.addParameter("openid_url", oid);
			postMethod_.addParameter("submit", "Login");
			int statusCode = webClient_.executeMethod(postMethod_);
			
			if (statusCode != HttpStatus.SC_OK) {
		        log.error("Method failed: " + postMethod_.getStatusLine());
		      }
			
			 // Read the response body.
		      byte[] responseBody = postMethod_.getResponseBody();

		      // Deal with the response.
		      // Use caution: ensure correct character encoding and is not binary data
		      System.out.println(new String(responseBody));
			
		} catch (Exception e) {
			e.printStackTrace();
		} 
		
		return null;
	}

	@Override
	public boolean sendResponse() {
		URI uri;
		try
		{
			createResponse();
			uri = new URI(PhoneIdpCommon.LISTEN_END_PT_URL, false);
			getMethod_.setURI(uri);
			
			//ArrayList<NameValuePair> pairs = new ArrayList<NameValuePair>();
			//pairs.add(new NameValuePair(PhoneIdpCommon.REQUEST_MODE, PhoneIdpCommon.VERIFY_RESPONSE_MODE));
			//pairs.add(new NameValuePair(OpenIdServlet.RESPONSE, response_.getSignedText_()));
			//getMethod_.setQueryString((NameValuePair[]) pairs.toArray());
			
			NameValuePair[] pairs = new NameValuePair[2];
			pairs[0] = new NameValuePair(PhoneIdpCommon.REQUEST_MODE, PhoneIdpCommon.VERIFY_RESPONSE_MODE);
			pairs[1] = new NameValuePair(OpenIdServlet.RESPONSE, response_.getSignedText_());
			getMethod_.setQueryString(pairs);
			
			
			log.info(getMethod_.toString());
			int statusCode = webClient_.executeMethod(getMethod_);
			
			if (statusCode != HttpStatus.SC_OK) {
		        log.error("Method failed: " + getMethod_.getStatusLine());
		      }
			
			 // Read the response body.
		      byte[] responseBody = getMethod_.getResponseBody();

		      // Deal with the response.
		      // Use caution: ensure correct character encoding and is not binary data
		      System.out.println(new String(responseBody));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		

		
		
		return false;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		log.info("HttpClient: Start");
		Client client = new HttpClientImpl();
		client.init();
		String name = "d1";
		String oid = "http://localhost:8080/joid/user/d1";
		
		//Register account
		//String sharedSecret = client.registerAccount(name, oid);
		
		//Challenge challenge = client.login(name, oid);
		
		
		//boolean result = client.sendResponse();
		client.sharedSecretIs("f9CsPzNDYuJWM+kBGB0v5OmprM4IzH2SrYnfsYD7ost0vIIknsOLROz+g4hip+osoCeZPNyYAw==");
		client.login(name, oid);
		client.authCodeIs("71Lua+5bjV21pUC8Tz9jog==");
		client.challengeIs(new ChallengeImpl(null, client.authCode()));
		client.sendResponse();
		
		
		//log.info("HttpClient: Result of verify is: " + result);		

	}

}
