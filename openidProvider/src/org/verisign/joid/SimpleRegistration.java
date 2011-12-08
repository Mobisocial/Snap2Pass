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

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

/**
 * Simple registration extensions, as defined by
 * http://openid.net/specs/openid-simple-registration-extension-1_0.html
 * 
 * <strong>This class should only be used by internal request/response 
 * processing</strong>. 
 * 
 * TODO to make this clearer.
 */
public class SimpleRegistration
{
    private final static Log log
	= LogFactory.getLog(SimpleRegistration.class);

    private Set required;
    private Set optional;
    private Map supplied;
    private String policyUrl;

    /** The <code>openid.sreg</code> value */
    public final static String OPENID_SREG = "openid.sreg"; 

    /** The <code>openid.ns.sreg</code> value */
    public final static String OPENID_SREG_NSDEF = "openid.ns.sreg";

    /** The <code>openid.sreg.required</code> value */
    public final static String OPENID_SREG_REQUIRED 
	= OPENID_SREG + ".required";

    /** The <code>openid.sreg.optional</code> value */
    public final static String OPENID_SREG_OPTIONAL 
	= OPENID_SREG + ".optional";

    /** The <code>openid.sreg.policy_url</code> value */
    public final static String OPENID_SREG_POLICY_URL 
	= OPENID_SREG + ".policy_url";

    /** Invalid namespace for sreg (from XRDS) seen in the wild */
    public final static String OPENID_SREG_NAMESPACE_10 = "http://openid.net/sreg/1.0";
    
    /** Standard namespace value for sreg */
    public final static String OPENID_SREG_NAMESPACE_11 = "http://openid.net/extensions/sreg/1.1";

    private final static String SREG_NICKNAME = "nickname";
    private final static String SREG_EMAIL = "email";
    private final static String SREG_FULLNAME = "fullname";
    private final static String SREG_DOB = "dob";
    private final static String SREG_GENDER = "gender";
    private final static String SREG_POSTCODE = "postcode";
    private final static String SREG_COUNTRY = "country";
    private final static String SREG_LANGUAGE = "language";
    private final static String SREG_TIMEZONE = "timezone";

    private String namespace;
    private String nickName;
    private String email;
    private String fullName;
    private String dob;
    private String gender;
    private String postCode;
    private String country;
    private String language;
    private String timeZone;

    /**
     * The set of the nine allowed SREG values.
     */
    public final static Set allowed = new HashSet();
    static {
	allowed.add(SREG_NICKNAME);
	allowed.add(SREG_EMAIL);
	allowed.add(SREG_FULLNAME);
	allowed.add(SREG_DOB);
	allowed.add(SREG_GENDER);
	allowed.add(SREG_POSTCODE);
	allowed.add(SREG_COUNTRY);
	allowed.add(SREG_LANGUAGE);
	allowed.add(SREG_TIMEZONE);
    }

    /**
     * Creates a simple registration. TODO: public for unit tests only.
     */
    public SimpleRegistration(Set required, Set optional, Map supplied,
			      String policyUrl)
    {
	this.required = required;
	this.optional = optional;
	this.supplied = supplied;
	this.policyUrl = policyUrl;
    this.namespace = OPENID_SREG_NAMESPACE_11;
    }
    

    /**
     * Creates a simple registration. TODO: public for unit tests only.
     */
    public SimpleRegistration(Set required, Set optional, Map supplied,
                              String policyUrl, String namespace)
    {
	this.required = required;
	this.optional = optional;
	this.supplied = supplied;
	this.policyUrl = policyUrl;
    this.namespace = namespace;
    }
    

    SimpleRegistration(Map map) throws OpenIdException
    {
	required = new HashSet();
	optional = new HashSet();
	supplied = new HashMap();
    namespace = OPENID_SREG_NAMESPACE_11;

	Set set = map.entrySet();
	for (Iterator iter = set.iterator(); iter.hasNext();){
	    Map.Entry mapEntry = (Map.Entry) iter.next();
	    String key = (String) mapEntry.getKey();
	    String value = (String) mapEntry.getValue();

	    if (OPENID_SREG_REQUIRED.equals(key)){
		addToSetFromList(required, value);
	    } else if (OPENID_SREG_OPTIONAL.equals(key)){
		addToSetFromList(optional, value);
	    } else if (OPENID_SREG_POLICY_URL.equals(key)){
		policyUrl = value; 
	    } else if (OPENID_SREG_NSDEF.equals(key)){
            if (OPENID_SREG_NAMESPACE_10.equals(value)
                || OPENID_SREG_NAMESPACE_11.equals(value)) {
                namespace = value; 
            }
        }
	}
    }

    public boolean isRequested()
    {
        return (!(required.isEmpty() && optional.isEmpty()));
    }


    /**
     * Expects a map with values like "openid.sreg.nickname=blahblah" in it
     */
    public static SimpleRegistration parseFromResponse(Map map)
    {
	Set req = new HashSet();
	Set opt = new HashSet();
	Map sup = new HashMap();
    String ns = OPENID_SREG_NAMESPACE_11;

	String trigger = OPENID_SREG + ".";
	int triggerLength = trigger.length();
	Set set = map.entrySet();
	for (Iterator iter = set.iterator(); iter.hasNext();){
	    Map.Entry mapEntry = (Map.Entry) iter.next();
	    String key = (String) mapEntry.getKey();
	    String value = (String) mapEntry.getValue();
	    
	    if (key.startsWith(trigger)){
		sup.put(key.substring(triggerLength), value);
	    } else if (OPENID_SREG_NSDEF.equals(key)){
            if (OPENID_SREG_NAMESPACE_10.equals(value)
                || OPENID_SREG_NAMESPACE_11.equals(value)) {
                ns = value; 
            }
        }
	}
	return new SimpleRegistration(req, opt, sup, "", ns);
    }

    private void addToSetFromList(Set set, String value)
    {
	StringTokenizer st = new StringTokenizer(value, ",");
	while (st.hasMoreTokens()) {
	    String token = st.nextToken().trim();
	    if (allowed.contains(token)){
		set.add(token);
	    } else {
		log.info("Illegal sreg value: "+token);
	    }
	}
    }
   
    public String getPolicyUrl(){return policyUrl;}
    public Set getRequired(){return required;}  // clone?
    public Set getOptional(){return optional;}  // clone?

    public void setRequired(Set set){required = set;}
    public void setOptional(Set set){optional = set;}  

    public String getNamespace () { return namespace; }

    //public Map getSuppliedValues(){return supplied;}

    public Map getSuppliedValues()
    {
	Map map = new HashMap();
	addAllNonEmpty(supplied, map);
	return map;
    }

    private void addAllNonEmpty(Map from, Map to)
    { 
	Set set = from.entrySet();
	for (Iterator iter = set.iterator(); iter.hasNext();){
	    Map.Entry mapEntry = (Map.Entry) iter.next();
	    String key = (String) mapEntry.getKey();
	    String value = (String) mapEntry.getValue();
	    if (value != null){
		to.put(key, value);
	    }
	}
    }

    public String toString()
    {
	return "[SimpleRegistration required="+required
	    +", optional="+optional+", supplied="+supplied
	    +", policy url="+policyUrl
        +", namespace="+namespace+"]";
    }
}
