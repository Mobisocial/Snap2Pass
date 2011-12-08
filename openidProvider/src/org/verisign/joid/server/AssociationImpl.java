package org.verisign.joid.server;

import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;
import org.verisign.joid.AssociationRequest;
import org.verisign.joid.Crypto;

import java.util.Date;
import java.util.Calendar;
import java.math.BigInteger;
import java.text.SimpleDateFormat;

/**
 * User: treeder
 * Date: Jul 19, 2007
 * Time: 4:39:09 PM
 */
public class AssociationImpl implements org.verisign.joid.Association {

	private final static Log log = LogFactory.getLog(AssociationImpl.class);
    private Long id;
    private String mode;
    private String handle;
    private String secret;
    private Date issuedDate;
    private Long lifetime;
    private String associationType;

    // Not in db
    private String error;
    private String sessionType;
    private byte[] encryptedMacKey;
    private BigInteger publicKey;

    public boolean isSuccessful()
    {
	return (error == null);
    }

    public boolean isEncrypted()
    {
	return ((AssociationRequest.DH_SHA1.equals(sessionType))
		|| (AssociationRequest.DH_SHA256.equals(sessionType)));
    }

    /**
     * Hibernate mapping.
     */
    public Long getId() {return id;}

    /** Hibernate mapping. */
    public String getSecret() {return secret;}

    /** Hibernate mapping. */
    public void setSecret(String secret) {this.secret = secret;}

    /** Hibernate mapping. */
    public void setId(Long id) {this.id = id;}

    /** Hibernate mapping. */
    public String getMode() {return mode;}

    /** Hibernate mapping. */
    public void setMode(String s) {mode = s;}

    /** Hibernate mapping. */
    public String getHandle() {return handle;}

    /** Hibernate mapping. */
    public void setHandle(String s) {this.handle = s;}

    /** Hibernate mapping. */
    public Date getIssuedDate() {return issuedDate;}

    /** Hibernate mapping. */
    public void setIssuedDate(Date issuedDate)
    {
 	SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
 	Date tmp = issuedDate;
	sdf.format(tmp);
	this.issuedDate = tmp;
    }

    public Long getLifetime() {return lifetime;}

    /**
     *
     * @param lifetime in seconds for this association. Expires after.
     */
    public void setLifetime(Long lifetime) {this.lifetime = lifetime;}

    public String getAssociationType() {return associationType;}
    public void setAssociationType(String s) {this.associationType = s;}

    /**
     * Returns a string representation of this assocation.
     *
     * @return a string representation of this assocation.
     */
    public String toString()
    {
	String s = "[Association secret="+secret;
	if (encryptedMacKey != null) {
	    s += ", encrypted secret="+ Crypto.convertToString(encryptedMacKey);
	}
	if (publicKey != null) {
	    s += ", public key="+Crypto.convertToString(publicKey);
	}
	s+=", type="+associationType+", issuedDate="+issuedDate+"]";
	return s;
    }

    public String getError() {return error;}

    public String getErrorCode(){throw new RuntimeException("nyi");}

    public void setSessionType(String sessionType)
    {
	this.sessionType = sessionType;
    }
    public String getSessionType()
    {
	return sessionType;
    }

    /** Hibernate mapping. */
    public void setMacKey(byte[] macKey)
    {
	this.secret = Crypto.convertToString(macKey);
    }

    /** Hibernate mapping. */
    public byte[] getMacKey()
    {
	return Crypto.convertToBytes(secret);
    }

    public void setEncryptedMacKey(byte[] b)
    {
	encryptedMacKey = b;
    }

    public byte[] getEncryptedMacKey()
    {
	return encryptedMacKey;
    }

    public void setPublicDhKey(BigInteger pk){publicKey = pk;}
    public BigInteger getPublicDhKey(){return publicKey;}

    public boolean hasExpired()
    {
	Calendar now = Calendar.getInstance();
	log.debug("now: "+now.toString());
	Calendar expired = Calendar.getInstance();
	log.debug("issuedDate: "+issuedDate.toString());
	expired.setTime(issuedDate);
	expired.add(Calendar.SECOND, lifetime.intValue());
	log.debug("expired: "+expired.toString());
	log.debug("now.after(expired): "+now.after(expired));
	return now.after(expired);
    }
		    }
