package edu.stanford.prpl.phoneIdp.server.api;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public abstract class AccountEntry {
	
	protected Credential myCredential_;
	protected boolean isActive_;
	protected Map<String, AuthCode> outStandingAuthCodes_; //key: authcode string
	protected Map<String, AuthCode> validAuthCodes_; // key: authcode string
	
	public void setMyCredential(Credential myCredential) {
		this.myCredential_ = myCredential;
	}
	public Credential getMyCredential() {
		return myCredential_;
	}
	public void setActive(boolean isActive) {
		this.isActive_ = isActive;
	}
	public boolean isActive() {
		return isActive_;
	}

	public Map<String, AuthCode> getActiveAuthCodes() {
		return outStandingAuthCodes_;
	}
	public void setActiveAuthCodes(Map<String, AuthCode> activeAuthCodes) {
		outStandingAuthCodes_ = activeAuthCodes;
	}
	public Map<String, AuthCode> getValidAuthCodes() {
		return validAuthCodes_;
	}
	public void setValidAuthCodes(Map<String, AuthCode> validAuthCodes) {
		validAuthCodes_ = validAuthCodes;
	}
	
	@Override
	public String toString()
	{
		StringBuilder result = new StringBuilder();
		result.append("AccountEntry: \n");
		result.append(myCredential_.toString());
		result.append("\nisActive");
		result.append("\n ActiveAuthCodes: \n");
		
		for (Iterator<String> it = outStandingAuthCodes_.keySet().iterator(); it.hasNext();)
		{
			result.append(outStandingAuthCodes_.get(it.next()));
			result.append(",");
		}
		
		for (Iterator<String> it = validAuthCodes_.keySet().iterator(); it.hasNext();)
		{
			result.append(validAuthCodes_.get(it.next()));
			result.append(",");
		}
		
		return result.toString();
	}

}
