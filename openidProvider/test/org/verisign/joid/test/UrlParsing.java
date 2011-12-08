package org.verisign.joid.test;

import junit.framework.TestCase;
import junit.framework.Assert;
import org.verisign.joid.consumer.ServerAndDelegate;
import org.verisign.joid.consumer.Discoverer;

import java.io.IOException;

/**
 * User: treeder
 * Date: Jul 17, 2007
 * Time: 4:38:37 PM
 */
public class UrlParsing extends TestCase{
	
	public void testGettingServerAndDelegate() throws Exception {
		Discoverer discoverer = new Discoverer();

		ServerAndDelegate serverAndDelegate = discoverer.findIdServer("http://netevil.org/blog/2007/06/howto-set-yourself-up-with-an-openid");
		System.out.println(serverAndDelegate);
		Assert.assertEquals("https://api.screenname.aol.com/auth/openidServer", serverAndDelegate.getServer());
		Assert.assertEquals("http://openid.aol.com/wezfurlong", serverAndDelegate.getDelegate());

		serverAndDelegate = discoverer.findIdServer("http://www.windley.com/archives/2007/02/using_openid_delegation.shtml");
		System.out.println(serverAndDelegate);
		Assert.assertEquals("https://www.myopenid.com/server", serverAndDelegate.getServer());
		Assert.assertEquals("http://windley.myopenid.com", serverAndDelegate.getDelegate());
	}

    public void testYadisDiscovery() throws Exception
    {
        Discoverer discoverer = new Discoverer();
        ServerAndDelegate serverAndDelegate = new ServerAndDelegate();
//        discoverer.findWithYadis("http://www.yahoo.com", serverAndDelegate);
        discoverer.findWithYadis("https://www.google.com/accounts/o8/id", serverAndDelegate);
        System.out.println(serverAndDelegate);
    }
}
