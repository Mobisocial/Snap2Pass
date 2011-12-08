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
            // this single-page login doesn't care about a claimedID.
            // Demo only.
            
%>
<p align="center">
    <span style="font-size:20px; background-color:black; color:white; padding:5px;">You are logged in.&nbsp;&nbsp;</span><a href="/joid/snap2pass/logout.jsp">Logout</a>
    <div><img src="/joid/snap2pass/kitty.jpg"/></div>
</p>
<%

			return;            
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

    <script language='javascript' type='text/javascript' src='/joid/snap2pass/junction/flXHR/flXHR.js'></script>

    <script language='javascript' type='text/javascript' src='/joid/snap2pass/junction/json2.js'></script>
    <script language='javascript' type='text/javascript' src='/joid/snap2pass/junction/strophejs/src/b64.js'></script>
    <script language='javascript' type='text/javascript' src='/joid/snap2pass/junction/strophejs/src/md5.js'></script>
    <script language='javascript' type='text/javascript' src='/joid/snap2pass/junction/strophejs/src/sha1.js'></script>
    <script language='javascript' type='text/javascript' src='/joid/snap2pass/junction/strophejs/src/strophe.js'></script>
    <script language='javascript' type='text/javascript' src='/joid/snap2pass/junction/junction.js'></script>

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

<h1>Snap2Pass Demo</h1>

<h3>1. Get the Software.</h3>
<p>You'll need the Snap2Pass Android app on your phone. Click <a href="snap2pass.apk">this link</a> or snap <a href="qr.html" target="_BLANK">this QR</a> to get it.</p>
<p>When you first run Snap2Pass, you will be asked to install an additional piece of software. Sorry for the hassle.</p>
<h3>2. Get An Account.</h3>
<p>If you don't have one already, you'll need an account. Click <a href="register.jsp">here</a> to create one, and then click the button under the Snap2Pass application's menu to store it.</p>

<h3>3. Log In.</h3>
  <div id="divLogin">
    <!--<div id="closeQRDiv">X</div>-->
    <div id="QRText">Log in from your mobile:</div>
    <img class="qr" src="#"></img>
  </div>


<form action="index.jsp" method="post" id="loginForm" name="loginForm">
    <input type="hidden" name="query" value="<%=getParam(request, "query")%>"/>
    <input type="hidden" name="openid.realm"
           value="<%=getParam(request, "openid.realm")%>"/>
    <input type="hidden" name="username" class="username" value=""/>
    <input type="hidden" name="authkey" class="authkey" value=""/>
    <input type="hidden" name="data" class="data" value=""/>
</form>

<h3>4. Integrate.</h3>
<p>Snap2Pass can be dropped in to any site requiring authentication. Here's an example of what Snap2Pass could look like in <a href="gmail.html">GMail.</a> (It doesn't work right now.)</p>
</body>
</html>
