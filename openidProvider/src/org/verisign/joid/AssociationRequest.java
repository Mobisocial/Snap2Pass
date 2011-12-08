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

import java.math.BigInteger;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.net.URLEncoder;
import java.io.UnsupportedEncodingException;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

/**
 * Represents an OpenID association request.
 */
public class AssociationRequest extends Request
{
    private final static Log log
	= LogFactory.getLog(AssociationRequest.class);

    private String sessionType;
    private String associationType;
    private BigInteger dhModulus;
    private BigInteger dhGenerator;
    private BigInteger dhConsumerPublic;

    private static String OPENID_SESSION_TYPE = "openid.session_type";
    private static String OPENID_ASSOCIATION_TYPE = "openid.assoc_type";
    private static String OPENID_DH_MODULUS = "openid.dh_modulus";
    private static String OPENID_DH_GENERATOR = "openid.dh_gen";
    private static String OPENID_DH_CONSUMER_PUBLIC 
	= "openid.dh_consumer_public";

    /** <code>no-encryption</code> as per the specification. */
    public static String NO_ENCRYPTION = "no-encryption";

    /** <code>DH-SHA256</code> as per the specification. */
    public static String DH_SHA1 = "DH-SHA1";

    /** <code>DH-SHA256</code> as per the specification. */
    public static String DH_SHA256 = "DH-SHA256";

    /** <code>HMAC-SHA1</code> as per the specification. */
    public static String HMAC_SHA1 = "HMAC-SHA1";

    /** <code>HMAC-SHA256</code> as per the specification. */
    public static String HMAC_SHA256 = "HMAC-SHA256";

    /**
     * Returns a ref to the static strings for subsequent
     * reference equality check (that is, no 
     * <code>.equals()</code> needed)
     */
    static String parseSessionType(String s)
    {
	if (NO_ENCRYPTION.equals(s)){
	    return NO_ENCRYPTION;
	} else if (DH_SHA1.equals(s)){
	    return DH_SHA1;
	} else if (DH_SHA256.equals(s)){
	    return DH_SHA256;
	} else {
	    throw new IllegalArgumentException("Cannot parse session type: "
					       +s);
	}
    }

    Map toMap()
    {
	Map map = super.toMap();
       
	map.put(AssociationRequest.OPENID_SESSION_TYPE, sessionType);
	map.put(AssociationRequest.OPENID_ASSOCIATION_TYPE, 
		associationType);
	map.put(AssociationRequest.OPENID_DH_CONSUMER_PUBLIC, 
		Crypto.convertToString(dhConsumerPublic));

	return map;
    }

    
    /**
     * Returns a ref to the static strings for subsequent
     * reference equality check (that is, no 
     * <code>.equals()</code> needed)
     */
    static String parseAssociationType(String s)
    {
	if (HMAC_SHA1.equals(s)){
	    return HMAC_SHA1;
	} else if (HMAC_SHA256.equals(s)){
	    return HMAC_SHA256;
	} else {
	    throw new 
		IllegalArgumentException("Cannot parse association type: "+s);
	}
    }

    private static BigInteger parseDhModulus(String s)
    {
	return Crypto.convertToBigIntegerFromString(s);
    }

    private static BigInteger parseDhGenerator(String s)
    {
	return Crypto.convertToBigIntegerFromString(s);
    }

    private static BigInteger parseDhConsumerPublic(String s)
    {
	return Crypto.convertToBigIntegerFromString(s);
    }

    /**
     * Creates a standard association request. Default values are
     * <code>HMAC-SHA1</code> for association type, and <code>DH-SHA1</code>
     * for session type.
     *
     * @param crypto the Crypto implementation to use.
     * @return an AssociationRequest.
     * @throws OpenIdException 
     */
    public static AssociationRequest create(Crypto crypto) 
    {
	try {
	    BigInteger pubKey = crypto.getPublicKey();
	    Map map = new HashMap();
	    map.put("openid.mode","associate");
	    map.put(OPENID_ASSOCIATION_TYPE, HMAC_SHA1);
	    map.put(OPENID_SESSION_TYPE, DH_SHA1);
	    map.put(OPENID_NS, OPENID_20_NAMESPACE);
	    map.put(OPENID_DH_CONSUMER_PUBLIC, Crypto.convertToString(pubKey));
	    return new AssociationRequest(map, "associate");
	} catch (OpenIdException e) {
	    throw new IllegalArgumentException(e.toString());
	}
    }

    AssociationRequest(Map map, String mode) throws OpenIdException
    {
	super(map, mode);
	this.sessionType = NO_ENCRYPTION;  //default value
	this.associationType = HMAC_SHA1;  //default value

	this.dhModulus = DiffieHellman.DEFAULT_MODULUS;
	this.dhGenerator = DiffieHellman.DEFAULT_GENERATOR;
	
	Set set = map.entrySet();
	for (Iterator iter=set.iterator(); iter.hasNext();){
	    Map.Entry mapEntry = (Map.Entry) iter.next();
	    String key = (String) mapEntry.getKey();
	    String value = (String) mapEntry.getValue();

	    if (OPENID_SESSION_TYPE.equals(key)){
		this.sessionType = AssociationRequest.parseSessionType(value);
	    } 
	    else if (OPENID_ASSOCIATION_TYPE.equals(key)){
		this.associationType 
		    = AssociationRequest.parseAssociationType(value);
	    } 
	    else if (OPENID_DH_MODULUS.equals(key)){
		this.dhModulus = AssociationRequest.parseDhModulus(value);
	    } 
	    else if (OPENID_DH_GENERATOR.equals(key)){
		this.dhGenerator = AssociationRequest.parseDhGenerator(value);
	    } 
	    else if (OPENID_DH_CONSUMER_PUBLIC.equals(key)){
		this.dhConsumerPublic 
		    = AssociationRequest.parseDhConsumerPublic(value);
	    }
	}
	checkInvariants();
    }

    /**
     * Returns whether the session type in use is not encrypted.
     *
     * @return whether the session type is not encrypted.
     */
    public boolean isNotEncrypted()
    {
	return (AssociationRequest.NO_ENCRYPTION.equals(sessionType));
    }

    private void checkInvariants() throws OpenIdException
    {
	if (mode == null){
	    throw new OpenIdException("Missing mode");
	}
	if (associationType == null){
	    throw new OpenIdException("Missing association type");
	}
	if (sessionType == null){
	    throw new OpenIdException("Missing session type");
	}

	if (((sessionType.equals(AssociationRequest.DH_SHA1)) &&
	     (!associationType.equals(AssociationRequest.HMAC_SHA1)))
	    || 
	    ((sessionType.equals(AssociationRequest.DH_SHA256)) &&
	     (!associationType.equals(AssociationRequest.HMAC_SHA256))))
	{
	    throw new OpenIdException("Mismatch "+OPENID_SESSION_TYPE
				      +" and "+OPENID_ASSOCIATION_TYPE);
	}
	if ((sessionType.equals(AssociationRequest.DH_SHA1))
	    || (sessionType.equals(AssociationRequest.DH_SHA256))){
	    if (dhConsumerPublic == null){
		throw new OpenIdException("Missing "
					  +OPENID_DH_CONSUMER_PUBLIC);
	    }
	}
    }

    public Response processUsing(ServerInfo si)	throws OpenIdException
    {
	Store store = si.getStore();
	Crypto crypto = si.getCrypto();
	Association a = store.generateAssociation(this, crypto);
	store.saveAssociation(a);
	return new AssociationResponse(this, a, crypto);
    }

    /**
     * Returns the DH modulus.
     *
     * @return the DH modulus.
     */
    public BigInteger getDhModulus(){return this.dhModulus;}

    /**
     * Returns the DH generator.
     *
     * @return the DH generator.
     */
    public BigInteger getDhGenerator(){return this.dhGenerator;}

    /**
     * Returns the DH public value.
     *
     * @return the DH public value.
     */
    public BigInteger getDhConsumerPublic(){return this.dhConsumerPublic;}

    /**
     * Returns the association session type.
     *
     * @return the association session type.
     */
    public String getSessionType(){return this.sessionType;}

    /**
     * Returns the association type of this request.
     *
     * @return the association type.
     */
    public String getAssociationType(){return this.associationType;}

    public String toString()
    {
        return "[AssociationRequest "
            + super.toString()
            +", session type="+sessionType
            +", association type="+associationType
	    +"]";
    }
}
