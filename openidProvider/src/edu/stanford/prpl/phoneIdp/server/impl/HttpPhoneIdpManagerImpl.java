package edu.stanford.prpl.phoneIdp.server.impl;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import junit.framework.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.verisign.joid.server.OpenIdServlet;

import edu.stanford.prpl.phoneIdp.client.impl.HttpClientImpl;
import edu.stanford.prpl.phoneIdp.common.PhoneIdpCommon;
import edu.stanford.prpl.phoneIdp.common.api.Challenge;
import edu.stanford.prpl.phoneIdp.common.utils.ServletUtils;
import edu.stanford.prpl.phoneIdp.common.utils.ServletUtils.HeaderType;
import edu.stanford.prpl.phoneIdp.server.api.AccountEntry;
import edu.stanford.prpl.phoneIdp.server.api.Credential;
import edu.stanford.prpl.phoneIdp.server.api.HttpPhoneIdpManager;
import edu.stanford.prpl.phoneIdp.server.api.PhoneIdp;
import edu.stanford.prpl.phoneIdp.server.impl.PhoneIdpImpl;

public class HttpPhoneIdpManagerImpl extends HttpPhoneIdpManager {
	
	protected static final Log log = LogFactory.getLog(HttpPhoneIdpManagerImpl.class);
	
	private static HttpPhoneIdpManagerImpl theInstance;
	
	private HttpPhoneIdpManagerImpl()
	{
		phoneIdpImpl_ = PhoneIdpImpl.getInstance();
	}
	
	
	public static HttpPhoneIdpManagerImpl getInstance()
	{
		if (theInstance == null)
		{
			theInstance = new HttpPhoneIdpManagerImpl();
		}
		return theInstance;
	}

	@Override
	public boolean isVerified(HttpServletRequest req, HttpServletResponse resp) {
		try {
			ServletUtils.printHeaders(HeaderType.ATTRIBUTES, req);
			ServletUtils.printHeaders(HeaderType.PARAMETERS, req);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		String oid = req.getParameter(OpenIdServlet.OPENID);
		if (null == oid)
		{
			oid =  (String) req.getAttribute(OpenIdServlet.OPENID);
		}
		
		String authcode = req.getParameter(OpenIdServlet.AUTHCODE);
		
		boolean result =  phoneIdpImpl_.isVerified(oid, authcode);
		
		//todo instead fwd to holding page
		try {
			resp.getWriter().print(result);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return result;
	}

	@Override
	public void createAccount(HttpServletRequest req, HttpServletResponse resp) {
		try {
			ServletUtils.printHeaders(HeaderType.ATTRIBUTES, req);
			ServletUtils.printHeaders(HeaderType.PARAMETERS, req);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
		String user = req.getParameter(OpenIdServlet.USERNAME_ATTRIBUTE);
		String openId = req.getParameter(OpenIdServlet.OPENID);
		String openIdAttrib = (String) req.getAttribute(OpenIdServlet.OPENID);
		log.info("user: " + user);
		log.info("openIdAttrib: " + openIdAttrib);
		
		Assert.assertNotNull(openIdAttrib);
		Assert.assertNotNull(user);
		Credential userCred = phoneIdpImpl_.createAccount(user, openIdAttrib);
		
		req.getSession(true).setAttribute(OpenIdServlet.SHARED_SECRET, userCred.getSharedSecret());
	}
	
	@Override
	public void getUpdateAccountDetails(HttpServletRequest req, HttpServletResponse resp) {
		String oid = req.getParameter(OpenIdServlet.OPENID);
		if (null == oid)
		{
			oid =  (String) req.getAttribute(OpenIdServlet.OPENID);
		}
		
		log.info("openId: " + oid);
		Credential userCred = phoneIdpImpl_.getAccount(oid);
		
		req.getSession(true).setAttribute(OpenIdServlet.SHARED_SECRET, userCred.getSharedSecret());
		//resp.setHeader(OpenIdServlet.SHARED_SECRET, userCred.getSharedSecret());
		
		
	}

	@Override
	public void createChallenge(HttpServletRequest req, HttpServletResponse resp) {
		try {
			ServletUtils.printHeaders(HeaderType.ATTRIBUTES, req);
			ServletUtils.printHeaders(HeaderType.PARAMETERS, req);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		String mode = req.getParameter(PhoneIdpCommon.REQUEST_MODE);
		
		if (mode.equalsIgnoreCase(PhoneIdpCommon.CREATE_CHALLENGE_MODE))
		{
			String oid = req.getParameter(OpenIdServlet.OPENID);
			Assert.assertNotNull(oid);
			Challenge challenge = phoneIdpImpl_.createChallenge(oid);
			req.getSession(true).setAttribute(OpenIdServlet.CHALLENGE, challenge.getAuthCode());
			

			//todo instead fwd to holding page
			try {
				resp.getWriter().print(challenge.getAuthCode());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		else
		{
			log.error("HttpPhoneIdpManager.createChallenge: mode actual: " + mode + ". Mode expected: " + PhoneIdpCommon.CREATE_CHALLENGE_MODE);
			return;
		}

	}
	
	@Override
	public boolean isAccountValid(HttpServletRequest req, HttpServletResponse resp)
	{
		String oid = req.getParameter(OpenIdServlet.OPENID);
		if (null == oid)
		{
			oid =  (String) req.getAttribute(OpenIdServlet.OPENID);
		}
		log.info("openId: " + oid);
		
		boolean result = phoneIdpImpl_.isAccountVerified(oid);
		req.getSession(true).setAttribute(OpenIdServlet.PIDPVERIFIED_ATTRIBUTE, result);
		
		return result;
	}

	@Override
	public boolean deleteAccount(HttpServletRequest req,
			HttpServletResponse resp) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean verifyResponse(HttpServletRequest req,
			HttpServletResponse resp) {
		
		boolean result = false;

		try {
			ServletUtils.printHeaders(HeaderType.ATTRIBUTES, req);
			ServletUtils.printHeaders(HeaderType.PARAMETERS, req);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		String mode = req.getParameter(PhoneIdpCommon.REQUEST_MODE);
		
		if (mode.equalsIgnoreCase(PhoneIdpCommon.VERIFY_RESPONSE_MODE))
		{
			String response = req.getParameter(OpenIdServlet.RESPONSE);
			Assert.assertNotNull(response);
			result = phoneIdpImpl_.verifyResponse(response);
			req.getSession(true).setAttribute(OpenIdServlet.VERIFY_RESULT, result);
			

			//todo instead fwd to holding page
			try {
				resp.getWriter().print(result);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		else
		{
			log.error("HttpPhoneIdpManager.verifyResponse: mode actual: " + mode + ". Mode expected: " + PhoneIdpCommon.VERIFY_RESPONSE_MODE);
			
		}
		
		return result;
	}
	
	

}
