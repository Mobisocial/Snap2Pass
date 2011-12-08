package edu.stanford.prpl.phoneIdp.server.api;

public abstract class Registrar {
	
	protected AccountStore accountStore_;
	
	public abstract Credential createAccount(String name, String oid);
	
	public abstract boolean updateAccount(String oid);
	
	public abstract boolean deleteAccount(String oid);

}
