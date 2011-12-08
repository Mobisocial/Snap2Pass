package edu.stanford.prpl.phoneIdp.common.utils;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class ServletUtils {
	
	private static final Log log = LogFactory.getLog(ServletUtils.class);

	public enum HeaderType {
		PARAMETERS, ATTRIBUTES
	}
	
	
	public static void printHeaders(HeaderType headerOptions, HttpServletRequest req) 
		throws ServletException, IOException
	{
		Enumeration headerNames = null;
		if (headerOptions.equals(HeaderType.PARAMETERS))
		{
			headerNames = req.getParameterNames();
		}
		else if (headerOptions.equals(HeaderType.ATTRIBUTES))
		{
			
			headerNames = req.getAttributeNames();
		}
		
	
		String headers;
		
		boolean emptyEnum = false;
		if  ((null != headerNames) && (!headerNames.hasMoreElements()))
		{
			emptyEnum = true;				
		}
		if (emptyEnum)
		{
			log.info("no headers were passed of type: " + headerOptions.toString());
			
		}
		else
		{
			log.info("Header type: Name: Value");
			while (headerNames.hasMoreElements())
			{
				try
				{
					headers = (String) headerNames.nextElement();	
					
					if (headerOptions.equals(HeaderType.PARAMETERS))
					{
						log.info("Param : " + headers + ": " + req.getParameter(headers));
					}
					else if (headerOptions.equals(HeaderType.ATTRIBUTES))
					{
						log.info("Attrib : " + headers + ": " + req.getAttribute(headers));
					}
						
				}
				catch (Exception e)
				{
					e.printStackTrace();
				}
			}
		}
		
	}
		
}
