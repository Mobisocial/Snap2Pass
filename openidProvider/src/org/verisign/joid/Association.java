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

package org.verisign.joid;

import java.math.BigInteger;
import java.util.Date;

/**
 * An association.
 *
 * Implement this interface to represent an OpenID association.
 */

public interface Association
{
    /**
     * Returns whether this association is valid (was successful)
     *
     * @return true is successful; false otherwise.
     */
    public boolean isSuccessful();

    /**
     * Returns error as a string.
     *
     * @return error as a string, null if no error.
     */
    public String getError();

    /**
     * Returns error code as a string.
     *
     * @return error code as a string, null if no error string.
     */
    public String getErrorCode();

    /**
     * Returns the association's handle. This handle should be suitable
     * to put on the wire as part of the OpenID protocol.
     *
     * @return handle as a string, null if no handle yet available.
     */
    public String getHandle();

    /**
     * Sets the association's handle. This handle should be suitable
     * to put on the wire as part of the OpenID protocol.
     *
     * @param s handle as a string.
     */
    public void setHandle(String s);

    /**
     * Sets the date this association was issued.
     *
     * @param issuedDate the timestamp of issucance.
     */
    public void setIssuedDate(Date issuedDate); 

    /**
     * Sets the lifetime of this association.
     *
     * @param lifetime the lifetime in seconds.
     */
    public void setLifetime(Long lifetime);

    /**
     * Gets the lifetime of this association. This is static, that is,
     * current time is not taken into consideration.
     *
     * @return lifetime the lifetime in seconds.
     */
    public Long getLifetime();

    /**
     * Gets the OpenID protocol association type, for example "HMAC-SHA1".
     *
     * @return the association type.
     */
    public String getAssociationType();

    /**
     * Sets the OpenID protocol association type, for example "HMAC-SHA1".
     *
     * @param s the association type.
     */
    public void setAssociationType(String s);

    /**
     * Gets the OpenID protocol session type, for example "DH-SHA1".
     *
     * @return the session type.
     */
    public String getSessionType();

    /**
     * Sets the OpenID protocol session type, for example "DH-SHA1".
     *
     * @param sessionType the session type.
     */
    public void setSessionType(String sessionType);

    /**
     * Returns the MAC key for this association.
     *
     * @return the MAC key; null if key doesn't exist.
     */    
    public byte[] getMacKey();

    /**
     * Returns the public Diffie-Hellman key in use.
     *
     * @return the DH key.
     */    
    public BigInteger getPublicDhKey();

    /**
     * Sets the public Diffie-Hellman key in use.
     *
     * @param pk the public DH key.
     */    
    public void setPublicDhKey(BigInteger pk);

    /**
     * Returns whether the assocation negotiates an encrypted secret.
     *
     * @return true if the secret is encrypted; false otherwise.
     */    
    public boolean isEncrypted();

    /**
     * Sets the encrypted MAC key for this association.
     *
     * @param encryptedSecret the encrypted MAC key.
     */    
    public void setEncryptedMacKey(byte[] encryptedSecret);

    /**
     * Returns the encrypted MAC key for this association.
     *
     * @return the encrypted MAC key; null if key doesn't exist.
     */    
    public byte[] getEncryptedMacKey();

    /**
     * Returns whether this association has expired.
     *
     * @return whether this association has expired.
     */
    public boolean hasExpired();
}
