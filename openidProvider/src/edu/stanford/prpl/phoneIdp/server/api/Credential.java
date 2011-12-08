/**
 * 
 */
package edu.stanford.prpl.phoneIdp.server.api;

import java.io.IOException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * @author debangsu
 *
 */
public abstract class Credential {
	
	protected String friendlyName_;
	protected String openId_;
	protected byte[] sharedSecret_;
	
	public String getFriendlyName() {
		return friendlyName_;
	}


	public void setFriendlyName(String friendlyName) {
		friendlyName_ = friendlyName;
	}


	public String getOpenId() {
		return openId_;
	}


	public void setOpenId(String openId) {
		openId_ = openId;
	}

	//Returns base 64 encoded shared secret
	public String getSharedSecret() {
		return new BASE64Encoder().encode(sharedSecret_);
	}

	//Argument: Base64 encoded sharedSecret
	public void setSharedSecret(String encodedSharedSecret) {
		try
		{
			sharedSecret_ = new BASE64Decoder().decodeBuffer(encodedSharedSecret);
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}


	
	
	
	@Override
	public String toString()
	{
		String result;
		result = "Credential: Name: " + friendlyName_ + ", OpenId: " + openId_ + ", SharedSecret: " + getSharedSecret();
		return result;
	}
}
