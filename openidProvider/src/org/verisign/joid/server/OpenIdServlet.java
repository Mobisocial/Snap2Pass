package org.verisign.joid.server;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.verisign.joid.AuthenticationRequest;
import org.verisign.joid.Crypto;
import org.verisign.joid.OpenId;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.RequestFactory;
import org.verisign.joid.ServerInfo;
import org.verisign.joid.Store;
import org.verisign.joid.StoreFactory;
import org.verisign.joid.util.CookieUtils;
import org.verisign.joid.util.DependencyUtils;

import edu.stanford.prpl.junction.api.activity.ActivityDescription;
import edu.stanford.prpl.junction.impl.JunctionMaker;
import edu.stanford.prpl.phoneIdp.common.PhoneIdpCommon;
import edu.stanford.prpl.phoneIdp.server.api.HttpPhoneIdpManager;
import edu.stanford.prpl.phoneIdp.server.api.PhoneIdp;
import edu.stanford.prpl.phoneIdp.server.impl.HttpPhoneIdpManagerImpl;
import edu.stanford.prpl.phoneIdp.server.impl.PhoneIdpImpl;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;

/**
 * User: treeder
 * Date: Jul 18, 2007
 * Time: 4:50:33 PM
 */
public class OpenIdServlet extends HttpServlet
{
	private static Log log = LogFactory.getLog(OpenIdServlet.class);
	private static final long serialVersionUID = 297366254782L;
	private static OpenId openId;
	private Store store;
	private Crypto crypto;
	private String loginPage;
	public static final String USERNAME_ATTRIBUTE = "username";
	public static final String ID_CLAIMED = "idClaimed";
	public static final String QUERY = "query";
	public static final String COOKIE_AUTH_NAME = "authKey";
	public static final String COOKIE_USERNAME = "username";
	private static UserManager userManager;

	//DSG
	private HttpPhoneIdpManager phoneIdpManager_;
	public static final String SHARED_SECRET = "sharedSecret";
	public static final String OPENID = "openid.claimed_id";
	public static final String CHALLENGE = "challenge";
	public static final String RESPONSE = "response";
	public static final String VERIFY_RESULT = "verifyresult";
	public static final String AUTHCODE = "authcode";
	public static final String MODE = "mode";
	public static final String PIDPVERIFIED_ATTRIBUTE = "pidpverified";

	public void init(ServletConfig config) throws ServletException
	{
		super.init(config);
		String storeClassName = config.getInitParameter("storeClassName");
		String userManagerClassName = config.getInitParameter("userManagerClassName");
		store = StoreFactory.getInstance(storeClassName);
		MemoryStore mStore = (MemoryStore) store;
		mStore.setAssociationLifetime(600);
		userManager = (UserManager) DependencyUtils.newInstance(userManagerClassName);
		crypto = new Crypto();
		loginPage = config.getInitParameter("loginPage");
		String endPointUrl = config.getInitParameter("endPointUrl");
		openId = new OpenId(new ServerInfo(endPointUrl, store, crypto));

		//dsg 
		phoneIdpManager_ = HttpPhoneIdpManagerImpl.getInstance();
	}


	public void doGet(HttpServletRequest request,
			HttpServletResponse response)
	throws ServletException, IOException
	{
		String mode = request.getParameter(PhoneIdpCommon.REQUEST_MODE);
		
		if (mode != null)
		{
			if (mode.equalsIgnoreCase(PhoneIdpCommon.CREATE_CHALLENGE_MODE))
			{
				phoneIdpManager_.createChallenge(request, response);
			}
			else if (mode.equalsIgnoreCase(PhoneIdpCommon.VERIFY_RESPONSE_MODE))
			{
				phoneIdpManager_.verifyResponse(request, response);
			}
			else if (mode.equalsIgnoreCase(PhoneIdpCommon.IS_VERIFIED_MODE))
			{
				phoneIdpManager_.isVerified(request, response);
			}
		}
		else
		{
			doQuery(request.getQueryString(), request, response);
		}
	}

	public void doPost(HttpServletRequest request,
			HttpServletResponse response)
	throws ServletException, IOException
	{
		StringBuffer sb = new StringBuffer();
		Enumeration e = request.getParameterNames();
		while (e.hasMoreElements()) {
			String name = (String) e.nextElement();
			String[] values = request.getParameterValues(name);
			if (values.length == 0) {
				throw new IOException("Empty value not allowed: "
						+ name + " has no value");
			}
			try {
				sb.append(URLEncoder.encode(name, "UTF-8") + "="
						+ URLEncoder.encode(values[0], "UTF-8"));
			} catch (UnsupportedEncodingException ex) {
				throw new IOException(ex.toString());
			}
			if (e.hasMoreElements()) {
				sb.append("&");
			}
		}
		doQuery(sb.toString(), request, response);
	}


	public void doQuery(String query,
			HttpServletRequest request, HttpServletResponse response)
	throws ServletException, IOException
	{
		log("\nrequest\n-------\n" + query + "\n");
		if (!(openId.canHandle(query))) {
			returnError(query, response);
			return;
		}
		try {
			boolean isAuth = openId.isAuthenticationRequest(query);
			HttpSession session = request.getSession(true);
			String user = getLoggedIn(request);
			log.debug("[OpenIdServlet] Logged in as: " + user);

			if (request.getParameter(AuthenticationRequest.OPENID_TRUST_ROOT ) != null){
				session.setAttribute (
						AuthenticationRequest.OPENID_TRUST_ROOT,
						request.getParameter(AuthenticationRequest.OPENID_TRUST_ROOT));
			}
			if (request.getParameter(AuthenticationRequest.OPENID_RETURN_TO ) != null){
				session.setAttribute(
						AuthenticationRequest.OPENID_RETURN_TO,
						request.getParameter(AuthenticationRequest.OPENID_RETURN_TO));
			}

			if (isAuth && user == null) {
				// todo: should ask user to accept realm even if logged in, but only once
				// ask user to accept this realm
				RequestDispatcher rd = request.getRequestDispatcher(loginPage);
				request.setAttribute(QUERY, query);
				request.setAttribute(AuthenticationRequest.OPENID_REALM, request.getParameter(AuthenticationRequest.OPENID_REALM));
				session.setAttribute(QUERY, query);
				//if claimed_id is null then use identity instead (because of diffs between v2 & v1 of spec)
				if ( request.getParameter(AuthenticationRequest.OPENID_CLAIMED_ID) == null){
					session.setAttribute(
							AuthenticationRequest.OPENID_CLAIMED_ID,
							request.getParameter (AuthenticationRequest.OPENID_IDENTITY));
				} else {
					session.setAttribute(
							AuthenticationRequest.OPENID_CLAIMED_ID,
							request.getParameter (AuthenticationRequest.OPENID_CLAIMED_ID));
				}
				session.setAttribute(
						AuthenticationRequest.OPENID_REALM,
						request.getParameter(AuthenticationRequest.OPENID_REALM));

				//                rd.forward(request, response);
				response.sendRedirect(loginPage);
				return;
			}
			

			
			
			
			String s = openId.handleRequest(query);
			log("\nresponse\n--------\n" + s + "\n");
			if (isAuth) {
				
				//// DSG
				/*
				HttpPhoneIdpManagerImpl httpPhoneIdpManager_ = HttpPhoneIdpManagerImpl.getInstance();
				httpPhoneIdpManager_.getUpdateAccountDetails(request, response);
				*/
				
				AuthenticationRequest authReq = (AuthenticationRequest)
				RequestFactory.parse(query);
				//                String claimedId = (String) session.getAttribute(ID_CLAIMED);
				/* Ensure that the previously claimed id is the same as the just
                passed in claimed id. */
				String identity;
				if ( request.getParameter(AuthenticationRequest.OPENID_CLAIMED_ID) == null){
					identity = request.getParameter(AuthenticationRequest.OPENID_IDENTITY);
				} else {
					identity = authReq.getClaimedIdentity();
				}
				//if (getUserManager().canClaim(user, authReq.getClaimedIdentity())) {
				if (true) {
					//String returnTo = authReq.getReturnTo();
					String returnTo = (String) session.getAttribute(AuthenticationRequest.OPENID_RETURN_TO );
					String delim = (returnTo.indexOf('?') >= 0) ? "&" : "?";
					s = response.encodeRedirectURL(returnTo + delim + s);
					log.debug("sending redirect to: " + s);
					response.sendRedirect(s);
				} else {
					throw new OpenIdException("User cannot claim this id.");
				}

			} else {
				// Association request
				int len = s.length();
				PrintWriter out = response.getWriter();
				response.setHeader("Content-Length", Integer.toString(len));
				if (openId.isAnErrorResponse(s)) {
					response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				}
				out.print(s);
				out.flush();
			}
		} catch (OpenIdException e) {
			e.printStackTrace();
			response.sendError(HttpServletResponse
					.SC_INTERNAL_SERVER_ERROR, e.getMessage());
		}
	}

	/**
	 *
	 * @param request
	 * @return Username the user is logged in as
	 */
	public static String getLoggedIn(HttpServletRequest request)
	{
		String o = (String) request.getSession(true).getAttribute(USERNAME_ATTRIBUTE);
		if (o != null) return o;
		// check Remember Me cookies
		String authKey = CookieUtils.getCookieValue(request, COOKIE_AUTH_NAME, null);
		if (authKey != null) {
			String username = CookieUtils.getCookieValue(request, COOKIE_USERNAME, null);
			if (username != null) {
				// lets check the UserManager to make sure this is a valid match
				o = getUserManager().getRememberedUser(username, authKey);
				if (o != null) {
					request.getSession(true).setAttribute(USERNAME_ATTRIBUTE, o);
				}
			}
		}
		return o;
	}

	/**
	 *
	 * @param request
	 * @param username if null, will logout
	 */
	public static void setLoggedIn(HttpServletRequest request, String username){
		request.getSession(true).setAttribute(USERNAME_ATTRIBUTE, username);
	}

	private void returnError(String query, HttpServletResponse response)
	throws ServletException, IOException
	{
		Map map = RequestFactory.parseQuery(query);
		String returnTo = (String) map.get("openid.return_to");
		boolean goodReturnTo = false;
		try {
			URL url = new URL(returnTo);
			goodReturnTo = true;
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}

		if (goodReturnTo) {
			String s = "?openid.ns:http://specs.openid.net/auth/2.0"
				+ "&openid.mode=error&openid.error=BAD_REQUEST";
			s = response.encodeRedirectURL(returnTo + s);
			response.sendRedirect(s);
		} else {
			PrintWriter out = response.getWriter();
			// response.setContentLength() seems to be broken,
			// so set the header manually
			String s = "ns:http://specs.openid.net/auth/2.0\n"
				+ "&mode:error"
				+ "&error:BAD_REQUEST\n";
			int len = s.length();
			response.setHeader("Content-Length", Integer.toString(len));
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			out.print(s);
			out.flush();
		}
	}

	public void log(String s)
	{
		// todo: resolve issue with non-prime servlet container + log4j/commons and replace
		System.out.println(s);
	}

	/**
	 * This sets a session variable stating that the claimed_id for this request
	 * has been verified so we can now return back to the relying party.
	 *
	 * @param session
	 * @param claimedId
	 */
	public static void idClaimed(HttpSession session, String claimedId)
	{
		session.setAttribute(ID_CLAIMED, claimedId);
	}

	public static UserManager getUserManager()
	{
		if (null == userManager) {
			System.out.println("Warning: creating new userManager object");
			userManager = new MemoryUserManager();
		}
		return userManager;
	}
    

    public static ProviderActor getProviderActorInstance(HttpServletRequest request) {
        ProviderActor prov = new ProviderActor(request); // need to send IdP manager
        ActivityDescription desc = new ActivityDescription();
        desc.setActivityID("prpl.openid.auth");
        desc.setFriendlyName("OpenID Auth");
        
        // not sure if this is right :) will fix later.
        JSONObject mobilePlatform = new JSONObject();
        try {
        	mobilePlatform.put("platform", "android");
        	mobilePlatform.put("url","http://path/to/my.apk");
        } catch (Exception e) {}
        desc.addRolePlatform("authenticator", mobilePlatform);
        // TODO: set download location of mobile code
        
        JunctionMaker.getInstance("prpl.stanford.edu").newJunction(desc, prov);
        
        // store the jx session as our random data to be validated:
        ProviderActor.setSessionData(request, prov.getJunction().getSessionID());
        
        return prov;
        // probably put this in a map somewhere?
      }
}
