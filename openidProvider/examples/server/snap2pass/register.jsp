<%@ page import="java.net.URLEncoder" %>
<%@ page import="org.verisign.joid.AuthenticationRequest" %>
<%@ page import="org.verisign.joid.server.ProviderActor" %>
<%@ page import="org.verisign.joid.server.MemoryUserManager" %>
<%@ page import="org.verisign.joid.server.OpenIdServlet" %>
<%@ page import="org.verisign.joid.server.OpenIdServlet" %>
<%@ page import="org.verisign.joid.server.User" %>

<%
  MemoryUserManager userManager = (MemoryUserManager)OpenIdServlet.getUserManager();
  User user;
  
   String claimedId = (String) session.getAttribute(AuthenticationRequest.OPENID_CLAIMED_ID);
   if (claimedId != null) {
        String username = claimedId.substring(claimedId.lastIndexOf("/") + 1);
        user = ProviderActor.createUser(username);
   } else {
   		user = ProviderActor.createUser();
   }
   
  String generatedName=user.getUsername();
  String sharedSecret=user.getPassword();
  String creds = "{\"username\":\""+generatedName+"\",\"key\":\""+sharedSecret+"\"}";
  String qrURL = "http://chart.apis.google.com/chart?cht=qr&chs=350x350&chl="+URLEncoder.encode(creds);
%>

    <script type="text/javascript" 
     src="http://ajax.googleapis.com/ajax/libs/jquery/1.3.2/jquery.min.js"></script>
<script type="text/javascript">

$(function(){
    var username = '<%= generatedName %>';
    $('#usernameSpan').html(username); 
  }
);

</script>


<div>
Hi, I've made an account for you. The username is <span id="usernameSpan"></span>. Point your mobile here:
</div>
<!-- for a real system, we'd want to only add our ID once it's scanned so we don't get garbage. -->
<div>
<img src="<%=qrURL%>"/>
</div>