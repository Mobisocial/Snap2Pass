package examples.server;

import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;

/**
 * User: treeder
 * Date: Jul 30, 2007
 * Time: 9:32:39 PM
 */
public class UserUrlFilter implements Filter
{
    private static Log log = LogFactory.getLog(UserUrlFilter.class);
    private String idJsp;

    public void init(FilterConfig filterConfig) throws ServletException
    {
        idJsp = filterConfig.getInitParameter("idJsp");
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain) throws IOException, ServletException
    {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String s = request.getServletPath();
        s = URLDecoder.decode(s, "utf-8");
        log.debug("servletpath: " + s);
        String[] sections = s.split("/");
        log.debug("sections.length: " + sections.length);
        String redir = "";
        String contextPath = request.getContextPath();
        if (sections.length >= 2)
        {
            for (int i = 0; i < sections.length; i++)
            {
                String section = sections[i];
                log.debug("section: " + section);
                if (section.equals("user"))
                {
                    String username = sections[i + 1];
                    log.debug("username: " + username);
                    log.debug("forwarding to: " + contextPath + idJsp);
                    request.setAttribute("username", username);
                    forward(request, response, idJsp);
                    return;
                }
            }

        }
        filterChain.doFilter(req, res);
    }

    public void destroy()
    {
    }

    private void forward(HttpServletRequest
            request, HttpServletResponse
            response, String path) throws IOException, ServletException
    {
        request.getRequestDispatcher(path).forward(request, response);
    }
}
