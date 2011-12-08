//
// (C) Copyright 2007 VeriSign, Inc.  All Rights Reserved.
//
// VeriSign, Inc. shall have no responsibility, financial or
// otherwise, for any consequences arising out of the use of
// this material. The program material is provided on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.
//
// Distributed under an Apache License
// http://www.apache.org/licenses/LICENSE-2.0
//

package org.verisign.joid;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

/**
 * Produces requests from incoming queries.
 */
public class RequestFactory
{
    private final static Log log = LogFactory.getLog(RequestFactory.class);

    private RequestFactory(){}

    public static String OPENID_MODE = "openid.mode";
    public static String ASSOCIATE_MODE = "associate";
    public static String CHECKID_IMMEDIATE_MODE = "checkid_immediate";
    public static String CHECKID_SETUP_MODE = "checkid_setup";
    public static String CHECK_AUTHENTICATION_MODE = "check_authentication";

    /**
     * Parses a query into a request.
     *
     * @param query the query to parse.
     * @return the parsed request.
     * @throws OpenIdException if the query cannot be parsed into a known
     *  request.
     */
    public static Request parse(String query) 
	throws UnsupportedEncodingException, OpenIdException
    {
	Map map;
	try {
	    map = parseQuery(query);
	} catch (UnsupportedEncodingException e) {
 	    throw new OpenIdException("Error parsing "+query+": "
				      +e.toString());
	}

	String s = (String) map.get(OPENID_MODE);
	if (ASSOCIATE_MODE.equals(s)){
	    return new AssociationRequest(map, s);
	} else if (CHECKID_IMMEDIATE_MODE.equals(s) 
		   || CHECKID_SETUP_MODE.equals(s)){
	    return new AuthenticationRequest(map, s);
	} else if (CHECK_AUTHENTICATION_MODE.equals(s)){
	    return new CheckAuthenticationRequest(map, s);
	} else {
 	    throw new OpenIdException("Cannot parse request from "+query);
	}
    }

    /**
     * Parses a query into a map. 
     *
     * @param query the query to parse.
     * @return the parsed request.
     * @throws UnsupportedEncodingException if the string is not properly 
     *  UTF-8 encoded.
     */
    public static Map parseQuery(String query) 
    	throws UnsupportedEncodingException
    {
	return MessageParser.urlEncodedToMap(query);
    }

}
