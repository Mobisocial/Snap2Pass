package org.verisign.joid.server;

import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

import java.util.Date;
import java.text.SimpleDateFormat;

/**
 * User: treeder
 * Date: Jul 19, 2007
 * Time: 4:41:21 PM
 */
public class NonceImpl implements org.verisign.joid.Nonce
{
    private final static Log log = LogFactory.getLog(NonceImpl.class);
    private Long id;
    private String nonce;
    private Date checkedDate;

    /** Hibernate mapping. */
    public Long getId() {return id;}

    /** Hibernate mapping. */
    public void setId(Long id) {this.id = id;}

    /** Hibernate mapping. */
    public String getNonce() {return nonce;}
    /** Hibernate mapping. */
    public void setNonce(String s) {nonce = s;}

    /** Hibernate mapping. */
    public Date getCheckedDate() {return checkedDate;}

    /** Hibernate mapping. */
    public void setCheckedDate(Date date)
    {
 	SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
 	Date tmp = date;
	sdf.format(tmp);
	this.checkedDate = tmp;
    }

    /**
     * Returns a string representation of this nonce.
     *
     * @return a string representation of this nonce.
     */
    public String toString()
    {
	return "[Nonce nonce="+nonce+", checked="+checkedDate+"]";
    }
}
