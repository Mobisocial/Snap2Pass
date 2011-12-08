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

import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;
import org.verisign.joid.server.NonceImpl;

/**
 * A nonce in the database.
 */
public class Nonce extends NonceImpl implements org.verisign.joid.Nonce
{
    private final static Log log = LogFactory.getLog(Nonce.class);

}
