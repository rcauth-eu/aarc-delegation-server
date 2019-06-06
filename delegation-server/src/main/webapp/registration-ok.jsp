<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%--
  User: Jeff Gaynor
  Date: 9/25/11
  Time: 4:26 PM
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
<title>Registration Successful!</title>
<style>
tr {
  vertical-align: top;
}
th, td {
  text-align: left;
  background: white;
  padding: 8px;
}
</style>
</head>
<body>
<h2>Registration Successful!</h2>

<table>
<tr><th colspan="2">Client credentials:</th></tr>
<tr>
<td style="width: 100px">Client ID:</td>
<td style="width: 500px"><b>${client.identifier}</b></td>
</tr>
<tr>
<td>Client secret:</td>
<td><b>${client.secret}</b>
</tr>
</table>

<br><hr><br>

<table>
<tr><th colspan="2">Registration data:</th></tr>
<tr><td>Client name:</td>
<td><c:out value="${client.name}"/></td></tr>
<tr><td>Client description:</td>
<td><pre><c:out value="${client.description}"/></pre></td></tr>
<tr><td>Contact email:</td>
<td><c:out value="${client.email}"/></td></tr>
<tr><td>Home URL:</td>
<td><c:out value="${client.homeUri}"/></td></tr>
<%--<tr><td>Refresh Token lifetime:</td>
<td><c:set var="xxx" scope="session" value="${client.rtLifetime}"/><c:if test="${xxx > 0}"><c:out value="${client.rtLifetime/1000}"/> seconds</c:if></td></tr>--%>
<tr><td>Receive limited proxies:</td>
<td><c:out value="${client.proxyLimited}"/></td></tr>
<tr style="vertical-align: top"><td>Callback URLs:</td>
<td><c:forEach items="${client.callbackURIs}" var="uri">
<c:out value="${uri}"/><br></c:forEach></td></tr>
<tr style="vertical-align: top"><td>Requested scopes:</td>
<td><c:forEach items="${client.scopes}" var="scope">
<c:out value="${scope}"/><br></c:forEach></td></tr>
</table>

<br><br>IMPORTANT NOTE: It is the client's responsibility to store the identifier and secret.
Your client will need to use it
as needed to identify itself. Please keep these in a safe location. If you lose the secret, you will have to
re-regisiter. Be sure you copy the secret without line breaks (which some browsers will insert) or you will
get an invalid secret.
<p>
    An administrator will contact you once your registration request is approved. You cannot use this
    identifier code until you have been approved by the administrator.
</body>
</html>
