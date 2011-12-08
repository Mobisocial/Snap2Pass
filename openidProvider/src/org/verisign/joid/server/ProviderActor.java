package org.verisign.joid.server;

import java.util.HashMap;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.json.JSONObject;

import edu.stanford.prpl.junction.api.activity.JunctionActor;
import edu.stanford.prpl.junction.api.messaging.MessageHandler;
import edu.stanford.prpl.junction.api.messaging.MessageHeader;
import edu.stanford.prpl.phoneIdp.server.api.PhoneIdp;

public class ProviderActor extends JunctionActor {
	//private PhoneIdp mPhoneIdp;
	private HttpSession mSession;
	
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

	
	private static HashMap<String,String>randomnessForSessions = new HashMap<String,String>();
	public static boolean setSessionData(HttpServletRequest request, String data) {
		if (randomnessForSessions.containsKey(data)) return false;
		
		randomnessForSessions.put(data,request.getSession().getId());
		return true;
	}
	
	public static boolean sessionOwnsData(HttpServletRequest request, String data) {
		return (randomnessForSessions.containsKey(data) &&
				request.getSession().getId().equals(randomnessForSessions.get(data)));
	}
	
	private static boolean clearSessionData(HttpServletRequest request, String data) {
		if (sessionOwnsData(request,data)) {
			/*
			 * Note that the ID<=>session map is server-generated.
			 * A browser is not capable of setting the data associated with a session.
			 * So we don't need to worry about a replay attack.
			 * 
			 * The whole mapping from data to session is actually not needed,
			 * and is more of a sanity check.
			 * 
			 * BJD
			 */
			randomnessForSessions.remove(data);
			return true;
		}
		return false;
	}
	
	public ProviderActor(/*PhoneIdp idp,*/ HttpServletRequest request) {
		super("provider");
		
		//mPhoneIdp=idp;
		mSession = request.getSession(true);
	}

	public static User createUser(String username) {
		try {
			if (null != ((MemoryUserManager)OpenIdServlet.getUserManager()).getUser(username)) {
				System.out.println("User " + username + " already exists.");
				return null;
			}
			
			KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
			SecretKey key = keyGen.generateKey();
			String b64key = new String(Base64Coder.encode(key.getEncoded()));
			
			User user = new User(username,b64key);
			((MemoryUserManager)OpenIdServlet.getUserManager()).save(user);
			
		return user;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static User createUser() {
		String username = "user_"+UUID.randomUUID().toString().substring(30, 36);
		return createUser(username);
	}
	
	// I hate this, and will soon change it to
	// onMessageReceied() { ... }
	public MessageHandler getMessageHandler() {
		return new MessageHandler() {
			public void onMessageReceived(MessageHeader header, JSONObject json) {
				try {
					if (json.has("action")
							&& json.getString("action").equals("authenticate")
							&& json.has("authkey")
							&& json.has("username")) {
						// fields :: username, authtoken?
						// have: json.optString("authkey");
						
						// Using DSG's stuff:
						/*
						if (mPhoneIdp.verifyResponse("signedText")) {
							// login successful
						} else {
							// login failed
						}
						*/
						
						User user = ((MemoryUserManager)OpenIdServlet.getUserManager()).getUser(json.getString("username"));
						if (user == null) {
							System.out.println("could not find user " + json.getString("username") + " for logging in.");
							
						}
						
						// We'll wait for the browser redirect; 
						// code reenters in login.jsp
						
						
						
						
						/*
						String computedResult = computeBase64_HMAC(
								getJunction().getSessionID(),
								user.getPassword());
						
						System.out.println("computed result: " + computedResult);
						JSONObject response = new JSONObject();
						response.put("result", computedResult);
						response.put("from","provider");
						response.put("matches", json.getString("authkey").equals(computedResult)?"true":"false");
						
						getJunction().sendMessageToSession(response);
						
						if (json.getString("authkey").equals(computedResult)) {
							// send valid response to browser
							mSession.setAttribute(OpenIdServlet.VERIFY_RESULT, true);
						}
						*/
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		};
	}
	
	public static boolean validateUserResponse(String username, HttpServletRequest httpRequest) {
		MemoryUserManager manager =  (MemoryUserManager)OpenIdServlet.getUserManager();
		User user = manager.getUser(username);
		if (user == null) return false;
		
		String key =  user.getPassword(); // look up from user
		String data = httpRequest.getParameter("data");
		String response = httpRequest.getParameter("authkey");
		
		// make sure the random data is associated with the browser session.
		if (!sessionOwnsData(httpRequest,data)) {
			return false;
		}
		
		String result = computeBase64_HMAC(data,key);
		boolean answer = (result.equals(response));
		
		if (answer) {
			clearSessionData(httpRequest, data);
		}
		
		return answer;
	}
	
	private static String computeBase64_HMAC(String data, String key) {
		try {
	        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
	        
	        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
	        mac.init(signingKey);
	
	        // compute the hmac on input data bytes
	        byte[] rawHmac = mac.doFinal(data.getBytes());
	
	        // base64-encode the hmac
	        String ans = new String(Base64Coder.encode(rawHmac));
	        System.out.println("b64: " + ans);
	        return ans;
		} catch (Exception e) {
			e.printStackTrace();
			return "badanswer";
		}
	}
}