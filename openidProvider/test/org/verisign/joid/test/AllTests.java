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

package org.verisign.joid.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.verisign.joid.Association;
import org.verisign.joid.AssociationRequest;
import org.verisign.joid.AssociationResponse;
import org.verisign.joid.AuthenticationRequest;
import org.verisign.joid.AuthenticationResponse;
import org.verisign.joid.CheckAuthenticationRequest;
import org.verisign.joid.CheckAuthenticationResponse;
import org.verisign.joid.Crypto;
import org.verisign.joid.DiffieHellman;
import org.verisign.joid.MessageParser;
import org.verisign.joid.OpenId;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.Request;
import org.verisign.joid.RequestFactory;
import org.verisign.joid.Response;
import org.verisign.joid.ResponseFactory;
import org.verisign.joid.ServerInfo;
import org.verisign.joid.SimpleRegistration;
import org.verisign.joid.Store;
import org.verisign.joid.StoreFactory;
import org.verisign.joid.extension.PapeRequest;
import org.verisign.joid.extension.PapeResponse;
import org.verisign.joid.server.AssociationImpl;
import org.verisign.joid.server.MemoryStore;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;



public class AllTests extends TestCase
{
    private long defaultLifespan;

    public AllTests(String name) {super(name);}
    protected void setUp() throws Exception {
        super.setUp();
        defaultLifespan = MemoryStore.DEFAULT_LIFESPAN;
    }
    protected void tearDown() throws Exception {super.tearDown();}

    private static Crypto crypto = new Crypto();
    private static Store store = StoreFactory.getInstance(MemoryStore.class.getName());
    private static ServerInfo serverInfo = new ServerInfo("http://example.com",
							  store, crypto);

    public static Test suite() 
    {
        return new TestSuite(AllTests.class);
    }


    private static final SecureRandom srand;
    static {
        try {
            srand = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
	    throw new RuntimeException("No SHA1 prng??");
        }
    }

    BigInteger p = DiffieHellman.DEFAULT_MODULUS;
    BigInteger g = DiffieHellman.DEFAULT_GENERATOR;

    private AssociationResponse associate(DiffieHellman dh)
	throws Exception
    {
	BigInteger publicKey = dh.getPublicKey();

	String s = "openid.mode=associate&openid.assoc_type=HMAC-SHA1"
	    +"&openid.session_type=DH-SHA1&openid.dh_consumer_public=";

	s += URLEncoder.encode(Crypto.convertToString(publicKey), "UTF-8");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AssociationRequest);
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AssociationResponse);
	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AssociationResponse);
	AssociationResponse ar = (AssociationResponse) resp;
	return ar;
    }

    private AssociationResponse associate256(DiffieHellman dh)
	throws Exception
    {
	BigInteger publicKey = dh.getPublicKey();

	String s = "openid.mode=associate&openid.assoc_type=HMAC-SHA256"
	    +"&openid.session_type=DH-SHA1&openid.dh_consumer_public=";

	s += URLEncoder.encode(Crypto.convertToString(publicKey), "UTF-8");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AssociationRequest);

	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AssociationResponse);
	AssociationResponse foo = (AssociationResponse) resp;
	assertTrue(foo.getSessionType(),
		   "DH-SHA256".equals(foo.getSessionType()));
	assertTrue("HMAC-SHA256".equals(foo.getAssociationType()));
	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AssociationResponse);
	AssociationResponse ar = (AssociationResponse) resp;
	return ar;
    }

    
    public void testUrlToMap() throws Exception
    {
        String testStr = "path?foo=bar&baz=qux";
        Map map = MessageParser.urlEncodedToMap(testStr);
        assertTrue(map.size() == 2);
        assertTrue(((String)map.get("foo")).equals("bar"));
        assertTrue(((String)map.get("baz")).equals("qux"));
        testStr = "path?foo=bar;baz=qux";
        map = MessageParser.urlEncodedToMap(testStr);
        assertTrue(map.size() == 2);
        assertTrue(((String)map.get("foo")).equals("bar"));
        assertTrue(((String)map.get("baz")).equals("qux"));
    }


    public void testAssociationLifeLength() throws Exception
    {
	Association a = new AssociationImpl();
	a.setIssuedDate(new Date());
	a.setLifetime(new Long(1));
	assertFalse(a.hasExpired());
	Thread.sleep(1200);
	assertTrue(a.hasExpired());
    }

    public void testGetSharedSecret()
    {
        for (int i = 0; i < 3; i++) {
            DiffieHellman dh1 = new DiffieHellman(p,g);
            DiffieHellman dh2 = new DiffieHellman(p,g);

            BigInteger secret1 = dh1.getSharedSecret(dh2.getPublicKey());
            BigInteger secret2 = dh2.getSharedSecret(dh1.getPublicKey());

            assertEquals(secret1, secret2);
        }
    }
    
    public void test2() throws Exception
    {
	String s = Utils.readFileAsString("2.txt");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AssociationRequest);
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AssociationResponse);

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AssociationResponse);
	AssociationResponse ar = (AssociationResponse) resp2;

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getMacKey());
	assertTrue(null != ar.getEncryptedMacKey());
	assertTrue(null != ar.getDhServerPublic());
	assertTrue(null == ar.getErrorCode());
    }

    public void test2b() throws Exception
    {
	String s = Utils.readFileAsString("2.txt");

	OpenId openId = new OpenId(serverInfo);
	assertTrue(openId.isAssociationRequest(s));
	assertFalse(openId.isAuthenticationRequest(s));
    }

    // Test no encryption 1.1 association request
    public void testAssocNoEncryption() throws Exception
    {
	String s = Utils.readFileAsString("5.txt");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AssociationRequest);
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AssociationResponse);

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AssociationResponse);
	AssociationResponse ar = (AssociationResponse) resp2;

	assertTrue(null == ar.getSessionType());
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null != ar.getMacKey());
	assertTrue(null == ar.getEncryptedMacKey());
	assertTrue(null == ar.getDhServerPublic());
	assertTrue(null == ar.getErrorCode());
    }

    public void testMarshall() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();
	String s = Crypto.convertToString(privateKey);
	BigInteger b = Crypto.convertToBigIntegerFromString(s);
	assertEquals(privateKey, b);
	s = Crypto.convertToString(publicKey);
	b = Crypto.convertToBigIntegerFromString(s);
	assertEquals(publicKey, b);
    }

    public void testSchtuffTrustRoot() throws Exception
    {
	String s = "openid.identity=http%3A%2F%2Fhans.beta.abtain.com%2F"
	    +"&openid.mode=checkid_setup"
	    +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
	    +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
	    +"nce%3D2006-12-"
	    +"06T04%253A54%253A51ZQvGYW3"
	    +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F";

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
    }

    public void testOpenIdNetDemoTrustRoot() throws Exception
    {
	String s = "openid.mode=checkid_setup&"
	    +"openid.identity=http://hans.beta.abtain.com/&"
	    +"openid.return_to=http://openid.net/demo/helpe"
	    +"r.bml%3Fstyle%3Dclassic%26oic.time%3D11654216"
	    +"99-368eacd1483709faab32&"
	    +"openid.trust_root=http://%2A.openid.net/demo/&"
	    +"openid.assoc_handle=1c431e80-8545-11db-9ff5-1"
	    +"55b0e692653";
	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
    }

    public void testTrustRoot() throws Exception
    {
	String base = "openid.mode=checkid_setup&openid.identity="
	    +"http://my.identity&openid.return_to=http://a.example.com";

	String foo = base + "&openid.trust_root=http://*.example.com";
	Request req = RequestFactory.parse(foo);
	assertTrue(req instanceof AuthenticationRequest);

	foo = base + "&openid.trust_root=http://www.example.com";
	try {
	    RequestFactory.parse(foo);
	    fail("Should have thrown");
	} catch (OpenIdException e){}


	// Trust root     Return to
	// ----------     ---------
	// /a/b/c     =>  /a/b/c/d    ==> ok
	// /a/b/c     =>  /a/b        ==> not ok
	// /a/b/c     =>  /a/b/b      ==> not ok
	//

	base = "openid.mode=checkid_setup&openid.identity="
	    +"http://my.identity&openid.trust_root=http://example.com/a/b/c";

	foo = base + "&openid.return_to=http://example.com/a/b/c/d";
	req = RequestFactory.parse(foo);
	assertTrue(req instanceof AuthenticationRequest);

	foo = base + "&openid.return_to=http://example.com/a/b";
	try {
	    RequestFactory.parse(foo);
	    fail("Should have thrown");
	} catch (OpenIdException e){}

	foo = base + "&openid.return_to=http://example.com/a/b/b";
	try {
	    RequestFactory.parse(foo);
	    fail("Should have thrown");
	} catch (OpenIdException e){}

    }

    public void test3() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	assertFalse(ar.isVersion2());
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);

	// authenticate
	String s = Utils.readFileAsString("3bv1.txt");
	s += "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
	assertFalse(req.isVersion2());
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AuthenticationResponse);
	assertFalse(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	AuthenticationResponse authr = (AuthenticationResponse) resp2;
	assertFalse(authr.isVersion2());
    assertTrue(null == authr.getUrlEndPoint());
    
	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	String signature = authr.getSignature();
	assertTrue(signature != null);

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);


	// check that we can authenticate the signature
	//
	Map map = authr.toMap();
	CheckAuthenticationRequest carq
	    = new CheckAuthenticationRequest(map, "check_authentication");
	assertFalse(carq.isVersion2());

	resp = carq.processUsing(serverInfo);
	assertFalse(resp.isVersion2());
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertTrue(carp.isValid());
    }

    public void test3_badsig() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	assertFalse(ar.isVersion2());
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);

	// authenticate
	String s = Utils.readFileAsString("3bv1.txt");
	s += "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
	assertFalse(req.isVersion2());
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AuthenticationResponse);
	assertFalse(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	AuthenticationResponse authr = (AuthenticationResponse) resp2;
	assertFalse(authr.isVersion2());

	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	String signature = authr.getSignature();
	assertTrue(signature != null);

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);


	// check that the wrong signature doesn't authenticate
	//
	Map map = authr.toMap();
	map.put("openid.sig", "pO+52CAFEBABEuu0lVRivEeu2Zw=");
	CheckAuthenticationRequest carq 
	    = new CheckAuthenticationRequest(map, "check_authentication");

	resp = carq.processUsing(serverInfo);
	assertFalse(resp.isVersion2());
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertFalse(carp.isValid());
    }


    public void testSreg() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);


	// authenticate
	String s = Utils.readFileAsString("sreg.txt");
	s += "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);
	assertTrue(req.isVersion2());
	assertTrue(req instanceof AuthenticationRequest);
	SimpleRegistration sreg = ((AuthenticationRequest) req)
	    .getSimpleRegistration();
	Set set = sreg.getRequired();
	Map supplied = new HashMap();
	for (Iterator iter = set.iterator(); iter.hasNext();){
	    s = (String) iter.next();
	    supplied.put(s, "blahblah");
	} 
	sreg = new SimpleRegistration(set, Collections.EMPTY_SET, supplied, "");
	((AuthenticationRequest) req).setSimpleRegistration(sreg);

	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AuthenticationResponse);
	assertTrue(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	AuthenticationResponse authr = (AuthenticationResponse) resp2;
	assertTrue(authr.isVersion2());

	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	String signature = authr.getSignature();
	assertTrue(signature != null);

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);

	// check that we can authenticate the signaure
	//
	Map map = authr.toMap();
	CheckAuthenticationRequest carq 
	    = new CheckAuthenticationRequest(map, "check_authentication");

    // Check for sreg namespace
    if (resp.isVersion2()) {
        assertEquals((String)map.get("openid.ns.sreg"), 
                     SimpleRegistration.OPENID_SREG_NAMESPACE_11);
    }

	resp = carq.processUsing(serverInfo);
	assertTrue(resp.isVersion2());
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertTrue(carp.isValid());
    }

    String v2 = "http://specs.openid.net/auth/2.0";

    public void testVersion2() throws Exception
    {
	String s = Utils.readFileAsString("2.txt");
	s += "openid.ns="+v2;

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AssociationRequest);
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AssociationResponse);
	assertTrue(resp.isVersion2());

	s = resp.toUrlString();
	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2.isVersion2());
	assertTrue(resp2 instanceof AssociationResponse);

	AssociationResponse ar = (AssociationResponse) resp2;

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getMacKey());
	assertTrue(null != ar.getEncryptedMacKey());
	assertTrue(null != ar.getDhServerPublic());
	assertTrue(null == ar.getErrorCode());
	assertTrue(v2.equals(ar.getNamespace()));
    }


    public void test3version2() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);


	// authenticate
	String s = Utils.readFileAsString("3b.txt");
	s += "?openid.ns="+v2
	    + "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);

	assertTrue(req instanceof AuthenticationRequest);
	assertTrue(req.isVersion2());
	assertTrue(((AuthenticationRequest) req).getClaimedIdentity() == null);
	Response resp = req.processUsing(serverInfo);

	assertTrue(resp instanceof AuthenticationResponse);
	assertTrue(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	assertTrue(resp2.isVersion2());
	AuthenticationResponse authr = (AuthenticationResponse) resp;

	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	assertTrue(sigList.indexOf("claimed_id") == -1);
	String signature = authr.getSignature();
	assertTrue(signature != null);
	String namespace = authr.getNamespace();
	assertTrue(v2.equals(namespace));

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);


	// check that we can authenticate the signaure
	//
	Map map = authr.toMap();
	CheckAuthenticationRequest carq 
	    = new CheckAuthenticationRequest(map, "check_authentication");

	resp = carq.processUsing(serverInfo);
	assertTrue(resp.isVersion2());
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertTrue(carp.isValid());
    }

    public void test3version2_badsig() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);


	// authenticate
	String s = Utils.readFileAsString("3b.txt");
	s += "?openid.ns="+v2
	    + "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);

	assertTrue(req instanceof AuthenticationRequest);
	assertTrue(req.isVersion2());
	assertTrue(((AuthenticationRequest) req).getClaimedIdentity() == null);
	Response resp = req.processUsing(serverInfo);

	assertTrue(resp instanceof AuthenticationResponse);
	assertTrue(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	assertTrue(resp2.isVersion2());
	AuthenticationResponse authr = (AuthenticationResponse) resp;
    assertTrue(null != authr.getUrlEndPoint());

	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	assertTrue(sigList.indexOf("claimed_id") == -1);
	String signature = authr.getSignature();
	assertTrue(signature != null);
	String namespace = authr.getNamespace();
	assertTrue(v2.equals(namespace));

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);


	// Check that the wrong signature doesn't authenticate
	//
	Map map = authr.toMap();
	map.put("openid.sig", "pO+52CAFEBABEuu0lVRivEeu2Zw=");
	CheckAuthenticationRequest carq 
	    = new CheckAuthenticationRequest(map, "check_authentication");
	assertTrue(carq.isVersion2());

	resp = carq.processUsing(serverInfo);
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertFalse(carp.isValid());
    }


    public void test3_claimedid_noncecheck() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);


	// authenticate
	String s = Utils.readFileAsString("3c.txt");
	s += "?openid.ns="+v2
	    + "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);

	assertTrue(req instanceof AuthenticationRequest);
	assertTrue(req.isVersion2());
	assertTrue(((AuthenticationRequest) req).getClaimedIdentity() !=null);
	Response resp = req.processUsing(serverInfo);

	assertTrue(resp instanceof AuthenticationResponse);
	assertTrue(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	assertTrue(resp2.isVersion2());
	AuthenticationResponse authr = (AuthenticationResponse) resp;

	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	assertTrue(sigList.indexOf("claimed_id") != -1);
	String signature = authr.getSignature();
	assertTrue(signature != null);
	String namespace = authr.getNamespace();
	assertTrue(v2.equals(namespace));

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);


	// check that we can authenticate the signaure
	//
	Map map = authr.toMap();
	CheckAuthenticationRequest carq 
	    = new CheckAuthenticationRequest(map, "check_authentication");

	resp = carq.processUsing(serverInfo);
	assertTrue(resp.isVersion2());
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertTrue(carp.isValid());


	// A 2nd check auth should fail (nonce check)
	//
	try {
	    resp = carq.processUsing(serverInfo);
	    assertTrue(false); 
	} catch (OpenIdException e) {
	    // should throw
	}
    }

    public void testEndsWithEquals() throws Exception
    {
	String s = "openid.assoc_handle=%7BHMAC-SHA1%7D%7B44e56"
	    +"f1d%7D%7BqrHn2Q%3D%3D%7D&openid.identity=http%3A%"
	    +"2F%2Fmisja.pip.verisignlabs.com%2F&openid.mode=ch"
	    +"eckid_setup"
	    +"&openid.return_to=http%3A%2F%2Fradagast.biz%2Felg"
	    +"g2%2Fmod%2Fopenid_client%2Freturn.php%3Fresponse_"
	    +"nonce%3DR"
	    +"qyqPiwW&openid.sreg.optional=email%2Cfullname"
	    +"&openid.trust_root=";

	try {
	    // no longer throws an exception because an unspecified
	    // trust_root is assumed to be the return_to url
	    Request req = RequestFactory.parse(s);
	} catch (OpenIdException unexpected){
        assertTrue(false);
	}
    }

    public void testEmptyIdentity() throws Exception
    {
	String s = "openid.return_to=http%3A%2F%2Ftest.vladlife.c"
	    +"om%2Ffivestores%2Fclass.openid.php&openid.cancel_to"
	    +"=&openid.mode=checkid_setup&openid.identity=&openid"
	    +".trust_root=http%3A%2F%2Ftest.vladlife.com&";
	try {
	    Request req = RequestFactory.parse(s);
	    Response resp = req.processUsing(serverInfo);
	    assertTrue(false);
	} catch (OpenIdException expected){
	}
    }
    
    public void testMissingDhPublic() throws Exception
    {
	
	String s = "openid.mode=associate"
	    +"&openid.session_type=DH-SHA1";
	
	try {
	    Request req = RequestFactory.parse(s);
	    assertTrue(false);
	} catch (OpenIdException expected){

	}
    }

    /** Tests that 'realm' is treated just like 'trust_root' */
    public void testRealm() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);

	String s = "openid.return_to=http%3A%2F%2Fexample.com&ope"
	    +"nid.realm=http%3A%2F%2Fexample.com&openid.ns=http%"
	    +"3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.claimed_id"
	    +"=http%3A%2F%2Falice.example.com&openid.mode=checkid"
	    +"_setup&openid.identity=http%3A%2F%2Fexample.com&ope"
	    +"nid.assoc_handle="+ar.getAssociationHandle();

	Request req = RequestFactory.parse(s);
	Response resp = req.processUsing(serverInfo);
    }

    /** Tests that trailing slashes on URLs are *not* canonicalized.
     * That is: http://example.com is not equals to http://example.com/
     */
    public void testTrailing() throws Exception
    {
	String s = "openid.return_to=http%3A%2F%2Fexample.com&ope"
	    +"nid.realm=http%3A%2F%2Fexample.com/&openid.ns=http%"
	    +"3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.claimed_id"
	    +"=http%3A%2F%2Falice.example.com&openid.mode=checkid"
	    +"_setup&openid.identity=http%3A%2F%2Fexample.com&ope"
	    +"nid.assoc_handle=1b184cb";

	try {
	    Request req = RequestFactory.parse(s);
	    Response resp = req.processUsing(serverInfo);
	    assertTrue(false);
	} catch (OpenIdException expected){
	}
    }

    /** Tests that identity can change.
     */
    public void testChangeId() throws Exception
    {
	String s = "openid.identity=http%3A%2F%2Fhans.beta.abtain.com%2F"
	    +"&openid.mode=checkid_setup"
	    +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
	    +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
	    +"nce%3D2006-12-"
	    +"06T04%253A54%253A51ZQvGYW3"
	    +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
	    +"&openid.assoc_handle=ahandle";

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
	AuthenticationRequest ar = (AuthenticationRequest) req;
	assertFalse(ar.isIdentifierSelect());
	ar.setIdentity("http://newidentity.example.com");
	String x = ar.toUrlString();
	assertFalse(s.equals(x));
    }

    /** Tests that identity_select works.
     */
    public void testIdentitySelect() throws Exception
    {
	String s = "openid.identity="
	    +"http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
	    +"&openid.mode=checkid_setup"
	    +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
	    +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
	    +"nce%3D2006-12-"
	    +"06T04%253A54%253A51ZQvGYW3"
	    +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
	    +"&openid.assoc_handle=ahandle";

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
	AuthenticationRequest ar = (AuthenticationRequest) req;
	assertTrue(ar.isIdentifierSelect());
    }

    /** Tests that extensions work.
     */
    public void testExtensions() throws Exception
    {
	String s = "openid.identity="
	    +"http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
	    +"&openid.mode=checkid_setup"
	    +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
	    +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
	    +"nce%3D2006-12-"
	    +"06T04%253A54%253A51ZQvGYW3"
	    +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
	    +"&openid.assoc_handle=ahandle"
	    +"&openid.ns.sig=http%3A%2F%2Fcommented.org"
	    +"&openid.foo=happiness%20is%20a%20warm%20bun"
	    +"&openid.glass.bunion=rocky%20sassoon%20gluebird%20foolia";

	try {
	    Request req = RequestFactory.parse(s);
	    assertTrue(false);
	} catch (OpenIdException e) {
	    // expected: ns.sig cannot be redefined
	}
    }

    /** Tests that extensions work.
     */
    public void testExtensions2() throws Exception
    {
	String s = "openid.identity="
	    +"http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
	    +"&openid.mode=checkid_setup"
	    +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
	    +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
	    +"nce%3D2006-12-"
	    +"06T04%253A54%253A51ZQvGYW3"
	    +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
	    +"&openid.ns.foo=http%3A%2F%2Fcommented.org"
	    +"&openid.foo=trycke%20e%20for%20mycke"
	    +"&openid.foo.bar=jaha%20vadda%20nu%20da";

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
	AuthenticationRequest ar = (AuthenticationRequest) req;
	assertTrue(ar.isIdentifierSelect());

	Map map = ar.getExtensions();
	assertTrue(map.containsKey("ns.foo"));
	assertTrue(map.containsKey("foo"));
	assertTrue(map.containsKey("foo.bar"));
    }

    public void testAssociateSHA256 () throws Exception
    {
        String s = "openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            + "&openid.session_type=DH-SHA256"
            + "&openid.assoc_type=HMAC-SHA256"
            + "&openid.mode=associate"
            + "&openid.dh_consumer_public=AJvqGzvFfjNk4LYWn8ZHSM7QyQnvxaaYUNwpSn089xdgBJx2okrYOWPesAl1%2B1oosnKPej6WBN9h2glimmv2g80h%2FAkDHLWU692efHdVhxnt4ZryI9SWAP0CIbznMs%2BphjGev4nS%2B5bLSR0lAbtvS7YQhiwfCJVrK5RrwplhZPzM";

        Request req = RequestFactory.parse(s);
        assertTrue(req instanceof AssociationRequest);
        AssociationRequest areq = (AssociationRequest) req;
        assertTrue(areq.isVersion2());

        // should not cause an exception in diffiehellman 
        Response resp = req.processUsing(serverInfo);  
        assertTrue(resp instanceof AssociationResponse);
        AssociationResponse aresp = (AssociationResponse) resp;
        assertTrue(aresp.isVersion2());
        System.out.println("assoc resp: " + aresp.toString());
    }

    public void testAssociate20 () throws Exception
    {
        String s = "openid.dh_consumer_public=GXmne0vGvF%2Fw9RHrk4McrUgxq3dmwURoKPhkrVdtBVNZtRlulFau2SBf%2FFT7JRo5LEcqY5CrctJlk%2B7YFcAyOX9VGd%2BmPfIE6cGPCTxy26USiJgjMEFPtkIRzT1y8lC7ypXvjZ5p0Q1hSg%2FuKdz1v0RAPICrVUrZ%2FgASGuqIpvQ%3D"
            + "&openid.assoc_type=HMAC-SHA1"
            + "&openid.session_type=DH-SHA1"
            + "&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            + "&openid.mode=associate";

        Request req = RequestFactory.parse(s);
        assertTrue(req instanceof AssociationRequest);
        AssociationRequest areq = (AssociationRequest) req;
        assertTrue(areq.isVersion2());

        Response resp = req.processUsing(serverInfo);  
        assertTrue(resp instanceof AssociationResponse);
        AssociationResponse aresp = (AssociationResponse) resp;
        assertTrue(aresp.isVersion2());
        
        // validate 2.0 association response
        Set validParams = new HashSet(Arrays.asList(new String[] { 
                    "assoc_handle",
                    "assoc_type",
                    "dh_server_public",
                    "enc_mac_key",
                    "expires_in",
                    "mac_key",
                    "ns",
                    "session_type"}));
        String respStr = resp.toPostString();
        String[] respParamStrs = respStr.split("\n");
        for (int i = 0; i < respParamStrs.length; i++) {
            String name = respParamStrs[i].substring(0, respParamStrs[i].indexOf(":"));
            String value = respParamStrs[i].substring(respParamStrs[i].indexOf(":") + 1);
            assertTrue("'" + name + "' not a valid association response parameter", 
                       validParams.contains(name));
            if (name.equals("ns")) {
                assertTrue("Bad namespace: " + value,
                           value.equals("http://specs.openid.net/auth/2.0"));
            }
        }
    }

    public void testAssociate1x () throws Exception
    {
        String s = "openid.dh_consumer_public=GXmne0vGvF%2Fw9RHrk4McrUgxq3dmwURoKPhkrVdtBVNZtRlulFau2SBf%2FFT7JRo5LEcqY5CrctJlk%2B7YFcAyOX9VGd%2BmPfIE6cGPCTxy26USiJgjMEFPtkIRzT1y8lC7ypXvjZ5p0Q1hSg%2FuKdz1v0RAPICrVUrZ%2FgASGuqIpvQ%3D"
            + "&openid.assoc_type=HMAC-SHA1"
            + "&openid.session_type=DH-SHA1"
            + "&openid.mode=associate";

        Request req = RequestFactory.parse(s);
        assertTrue(req instanceof AssociationRequest);
        AssociationRequest areq = (AssociationRequest) req;
        assertFalse(areq.isVersion2());

        Response resp = req.processUsing(serverInfo);  
        assertTrue(resp instanceof AssociationResponse);
        AssociationResponse aresp = (AssociationResponse) resp;
        assertFalse(aresp.isVersion2());
        
        // validate 1.1 association response
        Set validParams = new HashSet(Arrays.asList(new String[] { 
                    "assoc_handle",
                    "assoc_type",
                    "dh_server_public",
                    "enc_mac_key",
                    "expires_in",
                    "mac_key",
                    "session_type"}));
        String respStr = resp.toPostString();
        String[] respParamStrs = respStr.split("\n");
        for (int i = 0; i < respParamStrs.length; i++) {
            String[] tmp = respParamStrs[i].split(":");
            assertTrue("'" + tmp[0] + "' not a valid association response parameter", 
                       validParams.contains(tmp[0]));
        }
    }

    public void testAuthenticate1xWithInvalidParam () throws Exception
    {
        // Some RPs have been using the post_grant parameter that was
        // eliminated in 2005; for 1.x requests we should just ignore
        // unrecognized parameters
        String s = "openid.identity=http%3A%2F%2Fhans.beta.abtain.com%2F"
            +"&openid.mode=checkid_setup"
            +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
            +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
            +"nce%3D2006-12-"
            +"06T04%253A54%253A51ZQvGYW3"
            +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
            +"&openid.post_grant=return";
        try {
            Request req = RequestFactory.parse(s);
            assertTrue(req instanceof AuthenticationRequest);
        } catch (OpenIdException unexpected){
            assertTrue("Should not throw an exception on unrecognized parameter", false);
        }
    }

    public void testAuthenticate2xWithInvalidParam () throws Exception
    {
        String s = "openid.identity="
            +"http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
            +"&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            +"&openid.mode=checkid_setup"
            +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
            +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
            +"nce%3D2006-12-"
            +"06T04%253A54%253A51ZQvGYW3"
            +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
            +"&openid.foo=trycke%20e%20for%20mycke";
        try {
            Request req = RequestFactory.parse(s);
            assertTrue("Should throw an exception on unrecognized parameter", false);
            assertTrue(req instanceof AuthenticationRequest);
        } catch (OpenIdException expected) {}
    }

    // Check that the trust_root/realm gets set to the return_to
    // parameter if it is unspecified
    public void testAuthenticate2xDumbModeWithNoRealm () throws Exception
    {
        String s = "openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            + "&openid.claimed_id=http%3A%2F%2Ffoo.pip.verisignlabs.com%2F"
            + "&openid.identity=http%3A%2F%2Ffoo.pip.verisignlabs.com%2F"
            + "&openid.return_to=http%3A%2F%2Fbar.com%2Fadmin%2FLogin"
            + "&openid.mode=checkid_setup";
        try {
            Request req = RequestFactory.parse(s);
            assertTrue(req instanceof AuthenticationRequest);
            AuthenticationRequest areq = (AuthenticationRequest) req;
            assertEquals("trust_root should be equal to return_to", areq.getTrustRoot(), "http://bar.com/admin/Login");
        } catch (OpenIdException unexpected) {
            assertTrue("Should not throw an exception, threw '" + unexpected.getMessage() + "'", false);
        }
    }

    // Make sure that check authentication responses follow the 1.1 spec
    public void testSignatureValidation1xDumbMode () throws Exception
    {
        String s = "openid.identity=http%3A%2F%2Fidentity.bar.baz%2F"
            +"&openid.mode=checkid_setup"
            +"&openid.return_to=http%3A%2F%2Fwww.foo.bar%2F";
        try {
            // First get the stateless authentication request
            Request req = RequestFactory.parse(s);
            assertFalse(req.isVersion2());
            assertTrue(req instanceof AuthenticationRequest);
            AuthenticationRequest areq = (AuthenticationRequest) req;
            // Now construct the response
            Response resp = areq.processUsing(serverInfo);
            assertFalse(resp.isVersion2());
            assertTrue(resp instanceof AuthenticationResponse);
            AuthenticationResponse aresp = (AuthenticationResponse) resp;
            // Build the check authentication request from the auth response
            CheckAuthenticationRequest carq = new CheckAuthenticationRequest(aresp.toMap(), "check_authentication");
            assertFalse(carq.isVersion2());
            // Now get the check authentication response
            resp = carq.processUsing(serverInfo);
            assertFalse(resp.isVersion2());
            assertTrue(resp instanceof CheckAuthenticationResponse);
            CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
            assertTrue(carp.isValid());
            // Verify that the POST string for check auth response matches spec
            String respStr = carp.toPostString();
            System.out.println(respStr);
            Matcher m = Pattern.compile("^openid.mode:", Pattern.MULTILINE).matcher(respStr);
            assertTrue("Mode parameter 'openid.mode' must be in 1.x check auth responses", m.find());
            m = Pattern.compile("^is_valid:true$", Pattern.MULTILINE).matcher(respStr);
            assertTrue("Must have is_valid parameter in check auth response", m.find());
            m = Pattern.compile("^ns:", Pattern.MULTILINE).matcher(respStr);
            assertFalse("Must not have an ns parameter in 1.x check auth responses", m.find());
            // Parse the response string
            resp = ResponseFactory.parse(respStr);
            assertFalse(resp.isVersion2());
            assertTrue(resp instanceof CheckAuthenticationResponse);
        } catch (OpenIdException unexpected) {
            assertTrue("Should not throw an exception, threw '" + unexpected.getMessage() + "'", false);
        }
    }

    // Make sure that check authentication responses follow the 2.0 spec
    public void testSignatureValidation2xDumbMode () throws Exception
    {
        String s = "openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
            +"&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            +"&openid.mode=checkid_setup"
            +"&openid.return_to=http%3A%2F%2Fwww.foo.bar%2F";
        try {
            // First get the stateless authentication request
            Request req = RequestFactory.parse(s);
            assertTrue(req.isVersion2());
            assertTrue(req instanceof AuthenticationRequest);
            AuthenticationRequest areq = (AuthenticationRequest) req;
            // Now construct the response
            Response resp = areq.processUsing(serverInfo);
            assertTrue(resp.isVersion2());
            assertTrue(resp instanceof AuthenticationResponse);
            AuthenticationResponse aresp = (AuthenticationResponse) resp;
            // Build the check authentication request from the auth response
            CheckAuthenticationRequest carq = new CheckAuthenticationRequest(aresp.toMap(), "check_authentication");
            assertTrue(carq.isVersion2());
            // Now get the check authentication response
            resp = carq.processUsing(serverInfo);
            assertTrue(resp.isVersion2());
            assertTrue(resp instanceof CheckAuthenticationResponse);
            CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
            assertTrue(carp.isValid());
            // Verify that the POST string for check auth response matches spec
            String respStr = carp.toPostString();
            Matcher m = Pattern.compile("^(mode|openid.mode):", Pattern.MULTILINE).matcher(respStr);
            assertTrue("No mode value allowed in 2.x check auth responses", !m.find());
            m = Pattern.compile("^is_valid:true$", Pattern.MULTILINE).matcher(respStr);
            assertTrue("Must have is_valid parameter in check auth response", m.find());
            m = Pattern.compile("^ns:", Pattern.MULTILINE).matcher(respStr);
            assertTrue("Must have an ns parameter in 2.x check auth responses", m.find());
            // Parse the response string
            resp = ResponseFactory.parse(respStr);
            assertTrue(resp.isVersion2());
            assertTrue(resp instanceof CheckAuthenticationResponse);
        } catch (OpenIdException unexpected) {
            assertTrue("Should not throw an exception, threw '" + unexpected.getMessage() + "'", false);
        }
    }


    void validatePapeRequest (PapeRequest pr) throws Exception
    {
        assertTrue(pr.isValid());
        assertNotNull(pr.getMaxAuthAge());
        assertEquals(pr.getMaxAuthAge().intValue(), 3600);
        Collection policies = pr.getPreferredAuthPolicies();
        String[] pArray = { "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant",
                            "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
                            "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical" };
        Iterator it = policies.iterator();
        while (it.hasNext()) {
            String pStr = (String)it.next();
            int i = 0;
            for (i = 0; i < pArray.length; i++) {
                if (pStr.equals(pArray[i])) {
                    break;
                }
            }
            assertTrue(i < pArray.length);
        }

        String[] alnameArray = {
            "http://www.jisa.or.jp/spec/auth_level.html",
            "http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf" };
        List prefAuthLevels = pr.getPreferredAuthLevels();
        assertEquals(alnameArray.length, prefAuthLevels.size());
        for (int i = 0; i < alnameArray.length; i++) {
            assertTrue(alnameArray[i].equals((String) prefAuthLevels.get(i)));
        }
    }

    public void testPapeRequestFromQuery () throws Exception
    {
        String s = "openid.identity="
            +"http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
            +"&openid.mode=checkid_setup"
            +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
            +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
            +"nce%3D2006-12-"
            +"06T04%253A54%253A51ZQvGYW3"
            +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
            +"&openid.ns.foo=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0"
            +"&openid.foo.max_auth_age=3600"
            +"&openid.foo.preferred_auth_policies=http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fphishing-resistant+http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fmulti-factor+http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fmulti-factor-physical"
            +"&openid.foo.auth_level.ns.nist=http%3A%2F%2Fcsrc.nist.gov%2Fpublications%2Fnistpubs%2F800-63%2FSP800-63V1_0_2.pdf"
            +"&openid.foo.auth_level.ns.jisa=http%3A%2F%2Fwww.jisa.or.jp%2Fspec%2Fauth_level.html"
            +"&openid.foo.preferred_auth_level_types=jisa nist";

        Request req = RequestFactory.parse(s);
        assertTrue(req instanceof AuthenticationRequest);
        AuthenticationRequest ar = (AuthenticationRequest) req;
        assertTrue(ar.isIdentifierSelect());

        PapeRequest pr = new PapeRequest(ar.getExtensions());
        System.out.println(pr.toString());
        validatePapeRequest(pr);
        assertEquals(pr.getPreferredAuthPolicies().size(), 3);
    }

    public void testPapeRequestWithEmptyAuthPoliciesFromQuery () throws Exception
    {
        String s = "openid.identity="
            +"http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
            +"&openid.mode=checkid_setup"
            +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
            +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_nonce%3D2006-12-06T04%253A54%253A51ZQvGYW3"
            +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
            +"&openid.ns.foo=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0"
            +"&openid.foo.max_auth_age=3600"
            +"&openid.foo.preferred_auth_policies="
            +"&openid.foo.auth_level.ns.nist=http%3A%2F%2Fcsrc.nist.gov%2Fpublications%2Fnistpubs%2F800-63%2FSP800-63V1_0_2.pdf"
            +"&openid.foo.auth_level.ns.jisa=http%3A%2F%2Fwww.jisa.or.jp%2Fspec%2Fauth_level.html"
            +"&openid.foo.preferred_auth_level_types=jisa nist";

        Request req = RequestFactory.parse(s);
        assertTrue(req instanceof AuthenticationRequest);
        AuthenticationRequest ar = (AuthenticationRequest) req;
        assertTrue(ar.isIdentifierSelect());

        PapeRequest pr = new PapeRequest(ar.getExtensions());
        System.out.println(pr.toString());
        validatePapeRequest(pr);
        assertEquals(pr.getPreferredAuthPolicies().size(), 0);
    }

    public void testPapeRequestGenerate () throws Exception
    {
        String identity = "http://specs.openid.net/auth/2.0/identifier_select";
        String returnTo = "http://www.schtuff.com/?action=openid_return&dest=&stay_logged_in=False&response_nonce=2006-12-06t04%3A54%3A51ZQvGYW3";
        String trustRoot = "http://*.schtuff.com/";
        String assocHandle = "ahandle";
        AuthenticationRequest ar = AuthenticationRequest.create(identity,
                                                                returnTo,
                                                                trustRoot,
                                                                assocHandle);
        assertTrue(ar.isIdentifierSelect());
        PapeRequest pr = new PapeRequest();
        pr.setMaxAuthAge(3600);
        pr.setPreferredAuthPolicies(new String[] 
            { "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant",
              "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
              "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical" });
        pr.setPreferredAuthLevels(new String []
            { "http://www.jisa.or.jp/spec/auth_level.html",
              "http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf" });
        ar.addExtension(pr);
        PapeRequest pr1 = new PapeRequest(ar.getExtensions());
        validatePapeRequest(pr1);

        String s = ar.toUrlString();
        Request req = RequestFactory.parse(s);
        assertTrue(req instanceof AuthenticationRequest);
        AuthenticationRequest ar2 = (AuthenticationRequest) req;
        assertTrue(ar2.isIdentifierSelect());

        PapeRequest pr2 = new PapeRequest(ar2.getExtensions());
        System.out.println(pr2.toString());
        validatePapeRequest(pr2);
    }

    void validatePapeResponse (PapeResponse pr) throws Exception
    {
        assertTrue(pr.isValid());
        assertNotNull(pr.getAuthTime());
        assertEquals(pr.getAuthTime().getTime(), 1196510400000L);
        Collection policies = pr.getAuthPolicies();
        assertEquals(policies.size(), 3);
        String[] pArray = { "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant",
                            "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
                            "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical" };
        Iterator it = policies.iterator();
        while (it.hasNext()) {
            String pStr = (String)it.next();
            int i = 0;
            for (i = 0; i < pArray.length; i++) {
                if (pStr.equals(pArray[i])) {
                    break;
                }
            }
            assertTrue(i < pArray.length);
        }
        String[] alnameArray = {
            "http://www.jisa.or.jp/spec/auth_level.html",
            "http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf" };
        Set assuranceLevelSet = pr.getAuthAssuranceLevelSet();
        assertEquals(alnameArray.length, assuranceLevelSet.size());
        for (int i = 0; i < alnameArray.length; i++) {
            assertTrue(assuranceLevelSet.contains(alnameArray[i]));
        }
        assertTrue("2".equals(pr.getAuthAssuranceLevel("http://www.jisa.or.jp/spec/auth_level.html")));
        assertTrue("1".equals(pr.getAuthAssuranceLevel("http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf")));
    }

    public void testPapeResponseFromQuery () throws Exception
    {
        String s = "openid.op_endpoint=http%3A%2F%2Fexample.com"
            + "&openid.pape.auth_policies=http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fphishing-resistant+http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fmulti-factor+http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2Fmulti-factor-physical"
            + "&openid.pape.auth_time=2007-12-01T12%3A00%3A00Z"
            + "&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dopenid_return%26dest%3D%26stay_logged_in%3DFalse%26response_nonce%3D2006-12-06t04%253A54%253A51ZQvGYW3"
            + "&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            + "&openid.response_nonce=2007-10-15T17%3A38%3A16ZZvI%3D"
            + "&openid.pape.auth_level.ns.nist=http%3A%2F%2Fcsrc.nist.gov%2Fpublications%2Fnistpubs%2F800-63%2FSP800-63V1_0_2.pdf"
            + "&openid.pape.auth_level.ns.jisa=http%3A%2F%2Fwww.jisa.or.jp%2Fspec%2Fauth_level.html"
            + "&openid.pape.auth_level.nist=1"
            + "&openid.pape.auth_level.jisa=2"
            + "&openid.assoc_handle=694d5d70-7b45-11dc-8e68-bbf7f7e8a280"
            + "&openid.signed=assoc_handle%2Cidentity%2Cresponse_nonce%2Creturn_to%2Cclaimed_id%2Cop_endpoint"
            + "&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
            + "&openid.ns.pape=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0"
            + "&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
            + "&openid.mode=id_res"
            + "&openid.invalidate_handle=ahandle"
            + "&openid.sig=iqoAqcoyYK3XX9%2BOdxmdjUYLUJs%3D";

        Response resp = ResponseFactory.parse(s);
        assertTrue(resp instanceof AuthenticationResponse);
        AuthenticationResponse ar = (AuthenticationResponse) resp;
        assertTrue(ar.isVersion2());

        PapeResponse pr = new PapeResponse(ar.getExtensions());
        System.out.println(pr.toString());
        validatePapeResponse(pr);
    }
    
    public void testPapeResponseGenerate () throws Exception
    {
        String identity = "http://specs.openid.net/auth/2.0/identifier_select";
        String returnTo = "http://www.schtuff.com/?action=openid_return&dest=&stay_logged_in=False&response_nonce=2006-12-06t04%3A54%3A51ZQvGYW3";
        String trustRoot = "http://*.schtuff.com/";
        String assocHandle = "ahandle";
        AuthenticationRequest request = AuthenticationRequest.create(identity,
                                                                     returnTo,
                                                                     trustRoot,
                                                                     assocHandle);
        Response resp = request.processUsing(serverInfo);
        assertTrue(resp instanceof AuthenticationResponse);
        assertTrue(resp.isVersion2());
        AuthenticationResponse ar = (AuthenticationResponse)resp;
        PapeResponse pr = new PapeResponse();
        pr.setAuthTime(new Date(1196510400000L));
        assertTrue(pr.getParam("auth_policies").equals("http://schemas.openid.net/pape/policies/2007/06/none"));
        pr.setAuthPolicies(new String[]{});
        assertTrue(pr.getParam("auth_policies").equals("http://schemas.openid.net/pape/policies/2007/06/none"));
        pr.setAuthPolicies(new String[] 
            { "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant",
              "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
              "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical" });
        pr.setAuthAssuranceLevel("http://www.jisa.or.jp/spec/auth_level.html", "2");
        pr.setAuthAssuranceLevel("http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf", "1");
        ar.addExtension(pr);
        System.out.println(ar.toUrlString());
        String[] signed = ar.getSignedList().split(",");
        Set signSet = new HashSet();
        signSet.addAll(Arrays.asList(signed));
        assertTrue(signSet.contains("ns.pape"));
        assertTrue(signSet.contains("pape.auth_policies"));
        assertTrue(signSet.contains("pape.auth_time"));

        PapeResponse pr1 = new PapeResponse(ar.getExtensions());
        validatePapeResponse(pr1);

        String s = ar.toUrlString();
        System.out.println(s);
        Response req = ResponseFactory.parse(s);
        assertTrue(req instanceof AuthenticationResponse);
        AuthenticationResponse ar2 = (AuthenticationResponse) req;
        assertTrue(ar2.isVersion2());

        PapeResponse pr2 = new PapeResponse(ar2.getExtensions());
        System.out.println(pr2.toString());
        validatePapeResponse(pr2);
    }

    /*
     * Some RPs (*cough* blogger *cough*) have been known to use the
     * (invalid) http://openid.net/sreg/1.0 namespace for sreg in 2.0
     * requests.  If this happens we should return the same namespace
     * for interoperability reasons.
     */
    public void testSreg10 () throws Exception
    {
        String s = "openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            + "&openid.claimed_id=http%3A%2F%2Fhans.pip.verisignlabs.com%2F"
            + "&openid.identity=http%3A%2F%2Fhans.pip.verisignlabs.com%2F"
            + "&openid.return_to=https%3A%2F%2Fwww.blogger.com%2Fcomment.do%3FloginRedirect%3Dlm6phc1udus9"
            + "&openid.realm=https%3A%2F%2Fwww.blogger.com"
            + "&openid.mode=checkid_setup"
            + "&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fsreg%2F1.0"
            + "&openid.sreg.optional=nickname%2Cfullname";

        Request req = RequestFactory.parse(s);
        assertTrue(req instanceof AuthenticationRequest);
        AuthenticationRequest areq = (AuthenticationRequest) req;

        SimpleRegistration sreg = areq.getSimpleRegistration();
        assertTrue(sreg.isRequested());
        Set set = sreg.getOptional();
        Map supplied = new HashMap();
        for (Iterator iter = set.iterator(); iter.hasNext();){
            s = (String) iter.next();
            supplied.put(s, "blahblah");
        } 
        sreg = new SimpleRegistration(Collections.EMPTY_SET, set, supplied, "", sreg.getNamespace());
        areq.setSimpleRegistration(sreg);

        Response resp = req.processUsing(serverInfo);  
        assertTrue(resp instanceof AuthenticationResponse);
        AuthenticationResponse aresp = (AuthenticationResponse) resp;
        assertTrue(aresp.isVersion2());

        Map map = aresp.toMap();
        // Check for sreg namespace
        if (resp.isVersion2()) {
            assertEquals((String)map.get("openid.ns.sreg"), 
                         SimpleRegistration.OPENID_SREG_NAMESPACE_10);
        }
    }

    /* 
     * Check that normal sreg ns works
     */
    public void testSreg11 () throws Exception
    {
        String s = "openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            + "&openid.claimed_id=http%3A%2F%2Fhans.pip.verisignlabs.com%2F"
            + "&openid.identity=http%3A%2F%2Fhans.pip.verisignlabs.com%2F"
            + "&openid.return_to=https%3A%2F%2Fwww.blogger.com%2Fcomment.do%3FloginRedirect%3Dlm6phc1udus9"
            + "&openid.realm=https%3A%2F%2Fwww.blogger.com"
            + "&openid.mode=checkid_setup"
            + "&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1"
            + "&openid.sreg.optional=nickname%2Cfullname";

        Request req = RequestFactory.parse(s);
        assertTrue(req instanceof AuthenticationRequest);
        AuthenticationRequest areq = (AuthenticationRequest) req;

        SimpleRegistration sreg = areq.getSimpleRegistration();
        assertTrue(sreg.isRequested());
        Set set = sreg.getOptional();
        Map supplied = new HashMap();
        for (Iterator iter = set.iterator(); iter.hasNext();){
            s = (String) iter.next();
            supplied.put(s, "blahblah");
        } 
        sreg = new SimpleRegistration(Collections.EMPTY_SET, set, supplied, "", sreg.getNamespace());
        areq.setSimpleRegistration(sreg);

        Response resp = req.processUsing(serverInfo);  
        assertTrue(resp instanceof AuthenticationResponse);
        AuthenticationResponse aresp = (AuthenticationResponse) resp;
        assertTrue(aresp.isVersion2());

        Map map = aresp.toMap();
        // Check for sreg namespace
        if (resp.isVersion2()) {
            assertEquals((String)map.get("openid.ns.sreg"), 
                         SimpleRegistration.OPENID_SREG_NAMESPACE_11);
        }
    }

    /*
     * Any bad sreg ns gets converted to the proper 
     * http://openid.net/extensions/sreg/1.1
     */
    public void testSregBadNS () throws Exception
    {
        String s = "openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            + "&openid.claimed_id=http%3A%2F%2Fhans.pip.verisignlabs.com%2F"
            + "&openid.identity=http%3A%2F%2Fhans.pip.verisignlabs.com%2F"
            + "&openid.return_to=https%3A%2F%2Fwww.blogger.com%2Fcomment.do%3FloginRedirect%3Dlm6phc1udus9"
            + "&openid.realm=https%3A%2F%2Fwww.blogger.com"
            + "&openid.mode=checkid_setup"
            + "&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2Ffoo"
            + "&openid.sreg.optional=nickname%2Cfullname";

        Request req = RequestFactory.parse(s);
        assertTrue(req instanceof AuthenticationRequest);
        AuthenticationRequest areq = (AuthenticationRequest) req;

        SimpleRegistration sreg = areq.getSimpleRegistration();
        assertTrue(sreg.isRequested());
        Set set = sreg.getOptional();
        Map supplied = new HashMap();
        for (Iterator iter = set.iterator(); iter.hasNext();){
            s = (String) iter.next();
            supplied.put(s, "blahblah");
        } 
        sreg = new SimpleRegistration(Collections.EMPTY_SET, set, supplied, "", sreg.getNamespace());
        areq.setSimpleRegistration(sreg);

        Response resp = req.processUsing(serverInfo);  
        assertTrue(resp instanceof AuthenticationResponse);
        AuthenticationResponse aresp = (AuthenticationResponse) resp;
        assertTrue(aresp.isVersion2());

        Map map = aresp.toMap();
        // Check for sreg namespace
        if (resp.isVersion2()) {
            assertEquals((String)map.get("openid.ns.sreg"), 
                         SimpleRegistration.OPENID_SREG_NAMESPACE_11);
        }
    }

    public void testMessageMapToUrlStringOk () throws Exception
    {
        HashMap testMap = new HashMap ();
        testMap.put(CheckAuthenticationRequest.OPENID_ASSOC_HANDLE, "adfasdf");
        testMap.put("openid.mode", "check_authentication");
        testMap.put(AuthenticationResponse.OPENID_IDENTITY, "http://foo");
        testMap.put(AuthenticationResponse.OPENID_RETURN_TO, "http://bar");
        testMap.put(AuthenticationResponse.OPENID_NONCE, "42");
        testMap.put(AuthenticationResponse.OPENID_SIG, "siggy");

        CheckAuthenticationRequest testMessage = new CheckAuthenticationRequest(testMap, "check_authentication");
        String urlStr = testMessage.toUrlString();
        System.out.println("urlstr:\'" + urlStr + "'");
        String compareStr = "openid.assoc_handle=adfasdf&openid.identity=http%3A%2F%2Ffoo&openid.return_to=http%3A%2F%2Fbar&openid.sig=siggy&openid.mode=check_authentication&openid.response_nonce=42";
        assertTrue(compareStr.equals(testMessage.toUrlString()));
    }

    public void testMessageMapToUrlStringNullParam () throws Exception
    {
        HashMap testMap = new HashMap ();
        testMap.put(CheckAuthenticationRequest.OPENID_ASSOC_HANDLE, "adfasdf");
        testMap.put("openid.mode", "check_authentication");
        testMap.put(AuthenticationResponse.OPENID_IDENTITY, "http://foo");
        testMap.put(AuthenticationResponse.OPENID_RETURN_TO, "http://bar");
        testMap.put(AuthenticationResponse.OPENID_NONCE, null);
        testMap.put(AuthenticationResponse.OPENID_SIG, "siggy");

        boolean caught = false;
        try {
            CheckAuthenticationRequest testMessage = new CheckAuthenticationRequest(testMap, "check_authentication");
            String urlStr = testMessage.toUrlString();
        }
        catch (OpenIdException e) {
            caught = true;
        }
        assertTrue(caught);
    }

    public void testCheckAuthNonceOk () throws Exception
    {
        // first establish association
        String s = "openid.dh_consumer_public=GXmne0vGvF%2Fw9RHrk4McrUgxq3dmwURoKPhkrVdtBVNZtRlulFau2SBf%2FFT7JRo5LEcqY5CrctJlk%2B7YFcAyOX9VGd%2BmPfIE6cGPCTxy26USiJgjMEFPtkIRzT1y8lC7ypXvjZ5p0Q1hSg%2FuKdz1v0RAPICrVUrZ%2FgASGuqIpvQ%3D"
            + "&openid.assoc_type=HMAC-SHA1"
            + "&openid.session_type=DH-SHA1"
            + "&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            + "&openid.mode=associate";

        Request req = RequestFactory.parse(s);
        assertTrue(req instanceof AssociationRequest);
        AssociationRequest areq = (AssociationRequest) req;
        assertTrue(areq.isVersion2());

        Response resp = req.processUsing(serverInfo);  
        assertTrue(resp instanceof AssociationResponse);
        AssociationResponse aresp = (AssociationResponse) resp;
        assertTrue(aresp.isVersion2());

        // now do an auth req
        String areqStr = "openid.identity="
            +"http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
            +"&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            +"&openid.mode=checkid_setup"
            +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
            +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
            +"nce%3D2006-12-06T04%253A54%253A51ZQvGYW3"
            +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
            +"&openid.assoc_handle=" + aresp.getAssociationHandle();
        req = RequestFactory.parse(areqStr);
        assertTrue(req instanceof AuthenticationRequest);
        resp = req.processUsing(serverInfo);
        assertTrue(resp instanceof AuthenticationResponse);
        AuthenticationResponse authResp = (AuthenticationResponse) resp;
        String nonce = authResp.getNonce();

        // and check the response
        CheckAuthenticationRequest checkReq = new CheckAuthenticationRequest(authResp.toMap(), "check_authentication");
        resp = checkReq.processUsing(serverInfo);

        // do it again, using same assoc handle
        req = RequestFactory.parse(areqStr);
        assertTrue(req instanceof AuthenticationRequest);
        resp = req.processUsing(serverInfo);
        assertTrue(resp instanceof AuthenticationResponse);
        authResp = (AuthenticationResponse) resp;
        // make sure we didn't get the same nonce
        assertFalse(nonce.equals(authResp.getNonce()));

        // and check the 2nd response
        // since we didn't get the same nonce in the 2nd response we
        // shouldn't receive an exception claiming this is the case
        checkReq = new CheckAuthenticationRequest(authResp.toMap(), "check_authentication");
        resp = checkReq.processUsing(serverInfo);
    }

    public void testCheckAuthNonceDuplicate () throws Exception
    {
        // first establish association
        String s = "openid.dh_consumer_public=GXmne0vGvF%2Fw9RHrk4McrUgxq3dmwURoKPhkrVdtBVNZtRlulFau2SBf%2FFT7JRo5LEcqY5CrctJlk%2B7YFcAyOX9VGd%2BmPfIE6cGPCTxy26USiJgjMEFPtkIRzT1y8lC7ypXvjZ5p0Q1hSg%2FuKdz1v0RAPICrVUrZ%2FgASGuqIpvQ%3D"
            + "&openid.assoc_type=HMAC-SHA1"
            + "&openid.session_type=DH-SHA1"
            + "&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            + "&openid.mode=associate";

        Request req = RequestFactory.parse(s);
        assertTrue(req instanceof AssociationRequest);
        AssociationRequest areq = (AssociationRequest) req;
        assertTrue(areq.isVersion2());

        Response resp = req.processUsing(serverInfo);  
        assertTrue(resp instanceof AssociationResponse);
        AssociationResponse aresp = (AssociationResponse) resp;
        assertTrue(aresp.isVersion2());

        // now do an auth req
        String areqStr = "openid.identity="
            +"http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
            +"&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
            +"&openid.mode=checkid_setup"
            +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
            +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
            +"nce%3D2006-12-06T04%253A54%253A51ZQvGYW3"
            +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
            +"&openid.assoc_handle=" + aresp.getAssociationHandle();
        req = RequestFactory.parse(areqStr);
        assertTrue(req instanceof AuthenticationRequest);
        resp = req.processUsing(serverInfo);
        assertTrue(resp instanceof AuthenticationResponse);
        AuthenticationResponse authResp = (AuthenticationResponse) resp;
        String nonce = authResp.getNonce();

        // and check the response
        CheckAuthenticationRequest checkReq = new CheckAuthenticationRequest(authResp.toMap(), "check_authentication");
        Response newResp = checkReq.processUsing(serverInfo);

        // now try checking it again, using the same response
        // should get an exception indicating nonce reuse
        boolean caught = false;
        try {
            checkReq = new CheckAuthenticationRequest(authResp.toMap(), "check_authentication");
            newResp = checkReq.processUsing(serverInfo);
        }
        catch (OpenIdException e) {
            caught = true;
        }
        assertTrue(caught);
    }
}
