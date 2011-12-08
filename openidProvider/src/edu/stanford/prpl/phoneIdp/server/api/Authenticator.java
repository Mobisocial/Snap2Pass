/**
 * 
 */
package edu.stanford.prpl.phoneIdp.server.api;

import javax.servlet.http.HttpServlet;

import edu.stanford.prpl.phoneIdp.common.api.Challenge;
import edu.stanford.prpl.phoneIdp.common.api.Response;


/**
 * @author debangsu
 *
 */
public abstract class Authenticator {
	
	protected HttpServlet listenerServlet_;
	protected AccountStore accountStore_;
	protected AuthCodeCache authCodeCache_;
	
	public abstract Challenge generateChallenge(Credential cred);
	
	public abstract boolean verifyResponse(String signedText);
	
	public abstract boolean verifyResponse(Response resp);

}
