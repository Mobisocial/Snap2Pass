<%--
This page is a sample login page for OpenID SERVERS. You only need this if you are an OpenID provider. Consumers do NOT need this page.
--%>
<%@ page import="org.apache.commons.lang.RandomStringUtils" %>
<%@ page import="org.verisign.joid.AuthenticationRequest" %>
<%@ page import="org.verisign.joid.server.MemoryUserManager" %>
<%@ page import="org.verisign.joid.server.OpenIdServlet" %>
<%@ page import="org.verisign.joid.server.User" %>
<%@ page import="org.verisign.joid.util.CookieUtils" %>
<%@ page import="org.verisign.joid.util.UrlUtils" %>

<%@ page import="org.verisign.joid.server.ProviderActor" %>
<%!

    private MemoryUserManager userManager()
    {
        return (MemoryUserManager) OpenIdServlet.getUserManager();
    }

    private String getParam(HttpServletRequest request, String s)
    {
        String ret = (String) request.getAttribute(s);
        if (ret == null) {
            ret = request.getParameter(s);
        }
        // then try session
        if(ret == null){
            HttpSession session = request.getSession(true);
            ret = (String) session.getAttribute(s);
        }
        return ret;
    }

    private boolean authenticate(HttpServletRequest request, String username, String newuser)
    {

/*
        User user = userManager().getUser(username);
        System.out.println("have user " + user + " for " + username);
        if (user == null) {
            if (newuser != null) {
                //user = new User(username, password);
                //userManager().save(user);
                System.out.println("created new user: " + username);
            } else {
                return false;
            }
        }
*/
    String authkey = request.getParameter("authkey");
	User user = new User(username,authkey);
        if (ProviderActor.validateUserResponse(username,request)) {
            request.getSession(true).setAttribute(OpenIdServlet.USERNAME_ATTRIBUTE, user.getUsername());
            request.getSession(true).setAttribute("user", user);
            return true;
        }
        return false;
    }
%>
<%

	// used by both the provider servlet and the user's web browser.
   // how cool.

   // JSP passes access to Junction session to browser:
   ProviderActor provider = OpenIdServlet.getProviderActorInstance(request);
   String jxURI = provider.getJunction().getInvitationURI().toString();

    String errorMsg = null;
    // check if user is logging in.
    String username = request.getParameter("username");
    if (username != null) {
        if (authenticate(request, username, request.getParameter("newuser"))) {
            // ensure this user owns the claimed identity
            String claimedId = (String) session.getAttribute(AuthenticationRequest.OPENID_CLAIMED_ID);
			 if (claimedId != null) {
                // for this example app, the authenticated user must match the last
                // section of the openid.claimed_id, ie: /user/username
                String usernameFromClaimedId = claimedId.substring(claimedId.lastIndexOf("/") + 1);
                System.out.println("usernamefromurl: " + usernameFromClaimedId);
                if (username.equals(usernameFromClaimedId)) {
                    // call this to verify that this user owns the claimed_id
                    // todo: perhaps the claim(s) should be attached to the User object
                    OpenIdServlet.idClaimed(session, claimedId);
                    String query = request.getParameter("query");
                    // then we'll redirect to login servlet again to finish up
                    String baseUrl = UrlUtils.getBaseUrl(request);
                    String openIdServer = baseUrl + "/login";
                    response.sendRedirect(openIdServer + "?" + query);
                    return;
                } else {
                    errorMsg = "You do not own the claimed identity.";
                }
            }
            if(request.getParameter("rememberMe") != null){
                // store username and secret key combo for later retrieval and set cookies
                String secretKey = RandomStringUtils.randomAlphanumeric(128);
                CookieUtils.setCookie(response, OpenIdServlet.COOKIE_USERNAME, username);
                CookieUtils.setCookie(response, OpenIdServlet.COOKIE_AUTH_NAME, secretKey);
                userManager().remember(username, secretKey);
            }
        } else {
            // error for user side
            errorMsg = "Invalid login.";
        }
    }
%>
<html>
<head>

  <head>
    <script type="text/javascript" 
     src="http://ajax.googleapis.com/ajax/libs/jquery/1.3.2/jquery.min.js"></script>

    <script language='javascript' type='text/javascript' src='/joid/jx/junction/flXHR/flXHR.js'></script>

    <script language='javascript' type='text/javascript' src='/joid/jx/junction/json2.js'></script>
    <script language='javascript' type='text/javascript' src='/joid/jx/junction/strophejs/src/b64.js'></script>
    <script language='javascript' type='text/javascript' src='/joid/jx/junction/strophejs/src/md5.js'></script>
    <script language='javascript' type='text/javascript' src='/joid/jx/junction/strophejs/src/sha1.js'></script>
    <script language='javascript' type='text/javascript' src='/joid/jx/junction/strophejs/src/strophe.js'></script>
    <script language='javascript' type='text/javascript' src='/joid/jx/junction/junction.js'></script>

    <script type="text/javascript">

/* Login with Junction */

/*
  The session probably goes like this:
    <welcome to session 21938ABC803CAEF0>
    <provider has joined>
    <browser has joined>
    <phone has joined>
    phone: Hey, provider, my username is ABC and my authenticated secret is 123.
    provider: cool, you're good. Hey browser, redirect yourself to http://somewhere.
*/
function setupLoginListener(imgQuery) {
  var actor = {
    onMessageReceived: function(msg,header) {
      // look for a message intended for the browser role.
      // it will probably have a URL to redirect to.
      /*var res = "";
      for (key in msg) {
        res += key + ": " + msg[key] + "\n";
      }
      alert(res);*/

      if (msg.action && msg.action == 'authenticate') {
        $('#loginForm .username').val(msg.username);
        $('#loginForm .authkey').val(msg.authkey);
        $('#loginForm .data').val(this.junction.getSessionID());
	$('#loginForm').submit();
      }
    }
  };

  var jm = JunctionMaker.create();
  var jx = jm.newJunction('<%=jxURI%>',actor);

  var obj = $(imgQuery);
  var w = parseInt(($(obj).css('width')));
  if (w<=0) w=350;
  var invite = jx.getInvitationQR('phone',w);
  $(imgQuery).attr('src',invite);

}


$(function() {
  setupLoginListener('#divLogin img');
});
    </script>

  <style type="text/css">
#divLogin {
  text-align:center;
  background:#eef;
  border:1px solid #ccc; 
  padding:3px;
  margin:10px;
  z-index:1000;
  width: 600px;
}

#divLogin img {
  width:350px;
}

</style>

    <style type="text/css">
        .error {
            font-weight: bold;
            color: red;
        }
    </style>
</head>
<body>
<%
    if (errorMsg != null) {
%>
<div class="error"><%=errorMsg%>
</div>
<%
    }
%>

<h1>OpenID Provider Login</h1>
<p>New here? <a href="register.jsp">Create an account.</a></p>
<p>
We can avoid using this page if the Consumer is QR-Friendly. They can show a QR code on the consumer page directly. The authentication would happen directly between the phone and the provider, and the resulting auth token would be forwarded to the consumer by the phone (in the junction session)
</p>
  <div id="divLogin">
    <!--<div id="closeQRDiv">X</div>-->
    <div id="QRText">Log in from your mobile:</div>
    <img class="qr" src="#"></img>
  </div>
  <div>
    <p>Can't scan in? Enter your code here:</p>
    <input name="secret" value="yoursecret"/>
    <button id="handEnteredSecret">Log In</button>
  </div>


<form action="login.jsp" method="post" id="loginForm" name="loginForm">
    <input type="hidden" name="query" value="<%=getParam(request, "query")%>"/>
    <input type="hidden" name="openid.realm"
           value="<%=getParam(request, "openid.realm")%>"/>
    <input type="hidden" name="username" class="username" value=""/>
    <input type="hidden" name="authkey" class="authkey" value=""/>
    <input type="hidden" name="data" class="data" value=""/>
</form>






<!--

<form action="login.jsp" method="post">
    <input type="hidden" name="query" value="<%=getParam(request, "query")%>"/>
    <input type="hidden" name="openid.realm"
           value="<%=getParam(request, "openid.realm")%>"/>

    <p>
        Allow access to: <a href="<%=getParam(request, "openid.realm")%>"
                    target="_blank"><%=getParam(request, "openid.realm")%></a>?
    </p>
    <table border="0">
        <tr>
            <td>Username:</td>
            <td><input type="text" name="username"/></td>
        </tr>
        <tr>
            <td>Password:</td>
            <td><input type="password" name="password"/></td>
        </tr>
        <tr>
            <td>Create New User?</td>
            <td><input type="checkbox" name="newuser"/></td>
        </tr>
         <tr>
            <td>Remember Me?</td>
            <td><input type="checkbox" name="rememberMe"/></td>
        </tr>
        <tr>
            <td>&nbsp;</td>
            <td><input type="submit" value="Submit"/></td>
        </tr>
    </table>
</form>
<p>
    Logged in as: <%=session.getAttribute("user")%>
</p>
-->

</body>
</html>
