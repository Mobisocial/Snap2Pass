<%--
This page is a sample for consumers to use, but also serves as a testing page for running the server.
--%>
<%@ page import="org.verisign.joid.consumer.OpenIdFilter" %>
<%@ page import="org.verisign.joid.util.UrlUtils" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
	String returnTo = UrlUtils.getBaseUrl(request);
    if (request.getParameter("signin") != null) {
		try {
			String id = request.getParameter("openid_url");
			if (!id.startsWith("http")) {
				id = "http://" + id;
			}
			String trustRoot = returnTo;
			String s = OpenIdFilter.joid().getAuthUrl(id, returnTo, trustRoot);
			response.sendRedirect(s);
		} catch (Throwable e) {
			e.printStackTrace();
%>
An error occurred! Please press back and try again.
<%
		}
		return;
	}
%>
<html>
<head><title>OpenID Consumer Page: A Page I Want to Login To</title></head>
<body>
<h1>Login</h1>
<p>
	This is a sample login page where a user enters their OpenID url to login.
</p>

<%
    String loggedInAs = OpenIdFilter.getCurrentUser(session);
    if(loggedInAs != null){
%>
<p align="center">
    <span style="font-size:20px; background-color:black; color:white; padding:5px;">
    	You are logged in as: <%=OpenIdFilter.getCurrentUser(session)%></span> - <a href="logout.jsp">Logout</a>
    
    <br/> <br />
    <span style="font-size:18px; padding:5px;">
    	Shared secret is:  <%=OpenIdFilter.sharedSecret(session)%>
    	<br /> <br />
    	Phone Idp verified: <%=OpenIdFilter.pIdpVerified(session) %> 
    </span>
</p>

	
<%
    }
%>
<script type="text/javascript">
    function submitForm(url){
        document.getElementById("openid_url").value = url;
        document.getElementById("openid_form").submit();
    }
</script>
<div>
    <form action="index.jsp" method="post" id="openid_form">
        <input type="hidden" name="signin" value="true"/>
        <b>Login with your OpenID URL:</b>
        <input type="text" size="30" value="<%=returnTo+"/user/austinpowers"%>" name="openid_url" id="openid_url"/>
        <input type="submit" value="Login"/><br/>
        <i>For example: <tt>someone.bloghost.com</tt></i>
    </form>
</div>

<br/><br/>
    <img src="http://l.yimg.com/us.yimg.com/i/ydn/openid-signin-yellow.png" alt="Sign in with Yahoo" onclick="submitForm('http://www.yahoo.com');"/>
    <br/><br/>
    <img src="http://buttons.googlesyndication.com/fusion/add.gif" alt="Sign in with Google" onclick="submitForm('https://www.google.com/accounts/o8/id');"/>

<p>
    <strong>Don't have an OpenID?</strong> <a href="https://pip.verisignlabs.com/" target="_blank">Go</a>
    <a href="http://www.myopenid.com/" target="_blank">get</a>
    <a href="https://myvidoop.com/" target="_blank">one</a>.
</p>

</body>
</html>