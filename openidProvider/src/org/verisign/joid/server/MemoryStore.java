package org.verisign.joid.server;

import org.verisign.joid.Association;
import org.verisign.joid.AssociationRequest;
import org.verisign.joid.Crypto;
import org.verisign.joid.Nonce;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.Store;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ListIterator;


public class MemoryStore extends Store
{

	public static long DEFAULT_LIFESPAN = 300; // todo: should probably increase this
	private static List associationList = new ArrayList();
	private static List nonceList = new ArrayList();
	private long associationLifetime = DEFAULT_LIFESPAN;

	public Association generateAssociation(AssociationRequest req, 
			Crypto crypto) 
	throws OpenIdException
	{
		// boldly reusing the db implementation of Association
		AssociationImpl a = new AssociationImpl();
		a.setMode("unused");
		a.setHandle(Crypto.generateHandle());
		a.setSessionType(req.getSessionType());

		byte[] secret = null;
		if (req.isNotEncrypted()){
			secret = crypto.generateSecret(req.getAssociationType());
		} else {
			secret = crypto.generateSecret(req.getSessionType());
			crypto.setDiffieHellman(req.getDhModulus(), req.getDhGenerator());
			byte[] encryptedSecret 
			= crypto.encryptSecret(req.getDhConsumerPublic(), secret);
			a.setEncryptedMacKey(encryptedSecret);
			a.setPublicDhKey(crypto.getPublicKey());
		}
		a.setMacKey(secret);
		a.setIssuedDate(new Date());
		a.setLifetime(new Long(associationLifetime));

		a.setAssociationType(req.getAssociationType());
		return a;
	}

	public void saveAssociation(Association a)
	{
		associationList.add(a);
	}

	public void saveNonce(Nonce n)
	{
		nonceList.add(n);
	}

	public void deleteAssociation(Association a)
	{
		throw new RuntimeException("not yet implemented");
		// "associationList.delete(a)"
	}

	public Association findAssociation(String handle) throws OpenIdException
	{
		if (handle == null) return null;
		ListIterator li = associationList.listIterator();
		while (li.hasNext()){
			Association a = (Association) li.next();
			if (handle.equals(a.getHandle())){
				return a;
			}
		}
		return null;
	}

	public Nonce findNonce(String nonce) throws OpenIdException
	{
		if (nonce == null) return null;
		ListIterator li = nonceList.listIterator();
		while (li.hasNext()){
			Nonce n = (Nonce) li.next();
			if (nonce.equals(n.getNonce())){
				return n;
			}
		}
		return null;
	}

	public Nonce generateNonce(String nonce) throws OpenIdException
	{
		NonceImpl n = new NonceImpl();
		n.setNonce(nonce);
		n.setCheckedDate(new Date());
		return n;
	}

	public void setAssociationLifetime(long associationLifetime)
	{
		this.associationLifetime = associationLifetime;
	}
}
