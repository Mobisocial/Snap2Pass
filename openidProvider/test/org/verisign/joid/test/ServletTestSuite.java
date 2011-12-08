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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class ServletTestSuite extends TestCase
{
    public static void main(String[] args) 
    {
        junit.textui.TestRunner.run(ServletTestSuite.suite());
    }

    public static Test suite() 
    {
        TestSuite suite = new TestSuite();
        // TODO to be added... suite.addTest(IdpTestServlet.suite());
        return suite;
    }
}
