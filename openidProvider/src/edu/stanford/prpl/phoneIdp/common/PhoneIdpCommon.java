package edu.stanford.prpl.phoneIdp.common;

import org.verisign.joid.util.UrlUtils;

public class PhoneIdpCommon {
	
	public static String BASE_URL = "http://localhost:8080/joid";
	public static String LISTEN_END_PT_URL = BASE_URL + "/login";
	public static String RP_PAGE = "/index.jsp";
	
	public static long AUTHCODE_VALID_DURATION_MS = 10 * 60 * 1000; //10 mins in miliseconds
	
	public static String REQUEST_MODE = "mode";
	public static String CREATE_CHALLENGE_MODE = "createchallengemode";
	public static String VERIFY_RESPONSE_MODE = "verifyresponsemode";
	public static String IS_VERIFIED_MODE = "isverifiedmode";
}
