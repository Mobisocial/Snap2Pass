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

import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Iterator;

/**
 * Represents an OpenID check authentication request.
 */
public class CheckAuthenticationResponse extends Response
{
    private final static Log log
	= LogFactory.getLog(CheckAuthenticationResponse.class);

    private boolean isValid;

    static String OPENID_MODE = "openid.mode"; // for 1.1 messages
    static String OPENID_NS = "ns";
    static String OPENID_ERROR = "error";
    public static String OPENID_IS_VALID = "is_valid";
    public final static String OPENID_INVALIDATE_HANDLE = "invalidate_handle";

    private AuthenticationResponse ar;
    private Map map;
    private String invalidateHandle;

    /**
     * This constructor is for a Consumer side response received from the server.
     * @param map
     */
    public CheckAuthenticationResponse(Map map)
    {
        super(map);
        Set set = map.entrySet();
	for (Iterator iter = set.iterator(); iter.hasNext();){
	    Map.Entry mapEntry = (Map.Entry) iter.next();
	    String key = (String) mapEntry.getKey();
	    String value = (String) mapEntry.getValue();

	    if (OPENID_MODE.equals(key)) {
                mode = value;
	    } else if (OPENID_IS_VALID.equals(key)) {
                isValid = org.verisign.joid.util.Boolean.parseBoolean(value);
                //isValid = Boolean.parseBoolean(value);
            } else if (OPENID_INVALIDATE_HANDLE.equals(key)) {
                invalidateHandle = value;
            } else if (OPENID_NS.equals(key)) {
                ns = value;
            }
        }
    }

    /**
     * Returns whether this response contains notification that the request
     * signature was valid.
     *
     * @return true if the incoming </code>check_authentication</code> was
     * processed to be valid; false otherwise.
     */
    public boolean isValid() {return isValid;}

    /**
     * Returns the internal elements mapped to a map. The keys used
     * are those defined by the specification, for example <code>openid.mode</code>.
     *
     * TODO: Made public only for unit tests. Needs to package-scope
     * limit this method.
     *
     * @return a map with all internal values mapped to their specification
     * keys.
     */
    public Map toMap()
    {
	return map;
    }

    /**
     * throws at errors in signature creation
     */
    CheckAuthenticationResponse(AuthenticationResponse ar,
				Association a, Crypto crypto,
				String invalidateHandle)
	throws OpenIdException
    {
	super(Collections.EMPTY_MAP);
	this.ar = ar;
	this.ns = ar.getNamespace();

        map = new HashMap();
        if (isVersion2()) {
            map.put(OPENID_NS, OPENID_20_NAMESPACE);
        }

        if (a != null) {
            String sig = ar.sign(a.getAssociationType(),
                                 a.getMacKey(), ar.getSignedList());
            isValid = sig.equals(ar.getSignature());
        } else {
            isValid = false;
        }
        if (!isVersion2()) {
            map.put(OPENID_MODE, "id_res");
        }
        map.put(CheckAuthenticationResponse.OPENID_IS_VALID,
                isValid ? "true":"false");
        if (invalidateHandle != null) {
            map.put(CheckAuthenticationResponse.OPENID_INVALIDATE_HANDLE,
                    invalidateHandle);
        }
    }

    public String toString()
    {
        return "[CheckAuthenticationResponse "
            + super.toString()
            +", is valid="+isValid
	    +", authentication response="+ar
	    +"]";
    }

    public String getInvalidateHandle()
    {
        return invalidateHandle;
    }
}
