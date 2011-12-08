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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.net.URLEncoder;
import java.util.Properties;

public class Utils
{
    static String readFileAsString(String fileName) throws Exception
    {
	BufferedReader input = null;
	try {
	    File f = new File(fileName);
	    if (!f.exists()){
		throw new IllegalArgumentException("No such file: " 
						   + f.getCanonicalPath());
	    }
	    input = new BufferedReader(new FileReader(f));
	    String line = null;
	    StringBuffer contents = new StringBuffer();
	    while ((line = input.readLine()) != null){
		int n = line.indexOf('=');
		String name = URLEncoder.encode(line.substring(0, n), "UTF-8");
		String value 
		    = URLEncoder.encode(line.substring(n+1, line.length()),
					"UTF-8");
		contents.append(name+"="+value+"?");		
	    }
	    String s = contents.toString();
	    return s.substring(0, s.length());
	} finally {
	    if (input!= null) input.close();
	}
    }

    static Properties readFile(String fileName) throws Exception
    {
	File f = new File(fileName);
	if (!f.exists()){
	    throw new IllegalArgumentException("No such file: " 
					       + f.getCanonicalPath());
	}
	FileInputStream in = null;
	try {
	    Properties prop = new Properties();
	    in = new FileInputStream(f);
	    prop.load(in);
	    return prop;
	} finally {
	    if (in != null) try{in.close();}catch (Exception ignore){}
	}

    }

}
