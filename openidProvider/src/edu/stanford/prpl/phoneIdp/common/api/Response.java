package edu.stanford.prpl.phoneIdp.common.api;

import edu.stanford.prpl.phoneIdp.common.PhoneIdpCommon;

public abstract class Response {
	
	protected String destURL_;
	protected String signedText_;
	protected Challenge challenge_;
	
	protected String name_;
	protected String openId_;
	protected String realm_ = null; //optional
	protected String authCode_;
	protected String mode_ = PhoneIdpCommon.VERIFY_RESPONSE_MODE;
	protected String key_;
	
	public abstract Response createResponse();
	
	public String getAuthCode_() {
		return authCode_;
	}

	public void setAuthCode_(String authCode) {
		authCode_ = authCode;
	}
	
	public String getPlainText()
	{
		String plainText = "Name: " + name_ + ", OpenID: " + openId_ + ", Realm: " + realm_ + ", AuthCode = " + authCode_;
		return plainText;
	}
	
	public String getSignedText_() {
		return signedText_;
	}

	@Override
	public String toString()
	{
		String result = "Response: Plaintext: " + getPlainText();
		result += "\n";
		result += "SignedText: " + signedText_;
		return result;
	}
	
	
	

}
