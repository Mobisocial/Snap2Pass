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

package org.verisign.joid.db;

import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

/**
 * Manages Hibernate connections to our underlying database.
 *
 * Typical usecase:
 * <pre>
 * Session session = HibernateUtil.currentSession();
 * Transaction tx = session.beginTransaction();
 * ... do something with session ...
 * tx.commit();
 * HibernateUtil.closeSession();
 * </pre>
 */
public class HibernateUtil 
{
    private static final SessionFactory sessionFactory;

    private HibernateUtil() {}
    static {
        try {
            Configuration config = new Configuration()/*{
		    protected InputStream 
			getConfigurationInputStream(String resource)
			throws HibernateException 
		    {
			InputStream stream = null;
			stream = getClass().getResourceAsStream(resource);
			if (stream == null) {
			    throw new HibernateException(resource 
							 + " not found");
			}
			return stream;
		    }
		    }*/;
	    config.configure("org.verisign.joid.db.hibernate.cfg.xml");
            sessionFactory = config.buildSessionFactory();
        } catch (Throwable ex) {
            // Make sure you log the exception, as it might be swallowed
	    ex.printStackTrace();
            System.err.println("Initial SessionFactory creation failed." + ex);
            throw new ExceptionInInitializerError(ex);
        }
    }

    private static final ThreadLocal session = new ThreadLocal();

    /**
     * Returns the current database session. Opens a new session, if this 
     * thread has none yet.
     *
     * @return the current database session.
     *
     * @throws HibernateException if the Hibernate layer chokes. 
     */
    public static Session currentSession() throws HibernateException 
    {
        Session s = (Session) session.get();
        if (s == null) {
            s = sessionFactory.openSession();
            session.set(s);
        }
        return s;
    }

    /**
     * Closes the current database session.
     *
     * @throws HibernateException if the Hibernate layer chokes. 
     */
    public static void closeSession() throws HibernateException 
    {
        Session s = (Session) session.get();
        session.set(null);
        if (s != null) {
	    s.close();
	}
    }
}