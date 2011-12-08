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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

/**
 * Parses an OpenID message. 
 *
 * TODO: Made public only for unit tests. 
 */
public class MessageParser
{
    private final static Log log = LogFactory.getLog(MessageParser.class);
    static char newline = '\n'; 

    /**
     * Unrolls a message as a string. This string will use the
     * <code>name:value</code> format of the specification. See also
     * {@link #toUrlString()}.
     *
     * @return the message as a string.
     */
    static String toPostString(Message message) throws OpenIdException
    {
        return toStringDelimitedBy(message, ":", newline);
    }

    /**
     * Unrolls a message as a string. This string will use encoding
     * suitable for URLs. See also {@link #toPostString()}.
     *
     * @return the message as a string.
     */
    static String toUrlString(Message message) throws OpenIdException
    {
        return toStringDelimitedBy(message, "=", '&');
    }
 
    private static String toStringDelimitedBy(Message message,
					      String kvDelim, char lineDelim) throws OpenIdException
    {
	Map map = message.toMap();
	Set set = map.entrySet();
	StringBuffer sb = new StringBuffer();
	try {
	    for (Iterator iter=set.iterator(); iter.hasNext();){
		Map.Entry mapEntry = (Map.Entry) iter.next();
		String key = (String) mapEntry.getKey();
		String value = (String) mapEntry.getValue();

		if (lineDelim == newline){
		    sb.append(key+kvDelim+value);
		    sb.append(lineDelim);
		} else {
            if (value != null) {
                sb.append(URLEncoder.encode(key, "UTF-8")+kvDelim
                          +URLEncoder.encode(value, "UTF-8"));
                if (iter.hasNext()) {
                    sb.append(lineDelim);
                }
            }
            else {
                throw new OpenIdException("Value for key '" + key + "' is null in message map");
            }
		}

	    }
	    return sb.toString();
	} catch (UnsupportedEncodingException e){
	    // should not happen
	    throw new RuntimeException("Internal error");
	}
    }

    static int numberOfNewlines(String query) throws IOException
    {
	BufferedReader br = new BufferedReader(new StringReader(query));
	int n = 0;
	while (br.readLine() != null){n += 1;}
	//log.warn ("number of lines="+n+" for "+query);
	return n;
    }

    /**
     * Translate a query string to a Map.  
     *
     * TODO: Made public only for unit tests. Do not use.
     */
    public static Map urlEncodedToMap(String query) 
	throws UnsupportedEncodingException
    {
	Map map = new HashMap();
	if (query == null) {
	    return map;
	}
	StringTokenizer st = new StringTokenizer(query, "?&=;", true);
	String previous = null;
	while (st.hasMoreTokens()) {
	    String current = st.nextToken();
	    if ("?".equals(current) || "&".equals(current) || ";".equals(current)) {
		//ignore
	    } else if ("=".equals(current)) {
		String name = URLDecoder.decode(previous, "UTF-8");
		if (st.hasMoreTokens()){
		    String value = URLDecoder.decode(st.nextToken(), "UTF-8");
		    if (isGoodValue(value)){
			map.put(name, value);
		    }
		}
	    } else {
		previous = current;
	    }
	}
	return map;
    }

    private static boolean isGoodValue(String value)
    {
	if ("&".equals(value) || ";".equals(value)){
	    return false;
	}
	// more tests here perchance
	return true;
    }

    static Map postedToMap(String query) throws IOException
    {
	Map map = new HashMap();
	if (query == null) {
	    return map;
	}
	BufferedReader br = new BufferedReader(new StringReader(query));
	String s = br.readLine();
	while (s != null) {
	    int index = s.indexOf(":");
	    if (index != -1) {
		String name = s.substring(0, index);
		String value = s.substring(index+1, s.length());
		if (name != null && value != null){
		    map.put(name, value);
		}
	    }
	    s = br.readLine();
	}
	return map;
    }

}
