package examples.server;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.verisign.joid.Crypto;
import org.verisign.joid.OpenId;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.RequestFactory;
import org.verisign.joid.Store;
import org.verisign.joid.StoreFactory;

public class EchoServlet extends HttpServlet
{    
    private static final long serialVersionUID = 297364154782L;

    public void doGet(HttpServletRequest request, 
		      HttpServletResponse response)
        throws ServletException, IOException
    {
	doQuery(request, response);
    }

    public void doPost(HttpServletRequest request, 
                        HttpServletResponse response)
        throws ServletException, IOException
    {
	doQuery(request, response);
    }

    public void doQuery(HttpServletRequest request,
                        HttpServletResponse response)
        throws ServletException, IOException
    {
	PrintWriter out = response.getWriter();
	out.println(request.getQueryString());
	/*Enumeration e = request.getParameterNames();
	while (e.hasMoreElements()) {
	    String name = (String) e.nextElement();
	    String[] values = request.getParameterValues(name);
	    out.println(name+":"+values[0]);
	    }
	*/
	out.flush();
    }

}


