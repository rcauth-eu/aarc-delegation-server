<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<html>

<head>
    <title>RCauth Delegation Service (Online CA) Client Registration Page</title>
    <link rel="stylesheet" type="text/css" href="default.css" />
    <link rel="stylesheet" type="text/css" href="rcauth.css" />
</head>

<body>
<form action="${actionToTake}" method="post">

<div id="wrap">
  <div id="logoHolder">
    <div class="topLeft">
        <div id="topLogo" class="topLogo"><img src="RCauth-eu-logo-150.gif"><br/></div>
        <div id="topText" class="topText">The white-label Research and Collaboration Authentication CA Service for Europe</div>
    </div>
  </div>

  <div class="clear"></div>

  <div id=main>
    <h2>Welcome to the RCauth Client Registration Page</h2>

    <p>This page allows you to register your client with the
        RCauth delegation service that supports the OIDC/OAuth 2. To get your client approved,
        please fill out the form below. Your request will be evaluated for approval. For more information,
        please make sure you read the
        <a href="http://grid.ncsa.illinois.edu/myproxy/oauth/client/manuals/registering-with-an-oauth2-server.xhtml"
           target="_blank">Registering a Client with an OAuth 2 server</a> document.
    </p><br>
    <table>
        <tr>
            <td colspan="2"><b><font color="red"><c:out value="${retryMessage}"/></font></b></td>
        </tr>
        <tr>
            <td>Client Name:</td>
            <td><input type="text" size="25" name="${clientName}" value="<c:out value="${clientNameValue}"/>"/></td>
        </tr>
        <tr style="vertical-align: top">
            <td>Client Description:</td>
            <td>
                <textarea id="${clientDescription}" rows="10" cols="80"
                          name="${clientDescription}"><c:out value="${clientDescriptionValue}"/></textarea>
            </td>
        </tr>
        <tr>
            <td>Contact email:</td>
            <td><input type="text" size="25" name="${clientEmail}" value="<c:out value="${clientEmailValue}"/>"/></td>
        </tr>
        <tr>
            <td>Home URL:</td>
            <td><input type="text" size="25" name="${clientHomeUrl}" value="<c:out value="${clientHomeUrlValue}"/>"/></td>
        </tr>
<%--    <tr>
            <td ${rtFieldVisible}>Refresh Token lifetime:</td>
            <td ${rtFieldVisible}><input type="text" size="25" name="${rtLifetime}" value="<c:out value="${rtLifetimeValue}"/>"/>(in
                seconds - leave blank for no refresh tokens.)
            </td>
        </tr>--%>
        <tr>
            <td><span title="Check this box to receive only limited proxy certificates. Leave unchecked for EEC certificates.">
            Receive <B><I>only</I></B> limited proxies:</span></td>
            <td><input type="checkbox" name="${clientProxyLimited}" <c:out value="${clientProxyLimitedValue}"/> />
            </td>
        </tr>
<%--    <tr>
            <td>Issuer (optional):</td>
            <td><input type="text" size="25" name="${issuer}" value="<c:out value="${issuerValue}"/>"/></td>
        </tr>--%>
<%--    <tr style="vertical-align: top">
            <td><span title="Check this box if the client is to be public, i.e., limited access, no certificates allowed and no secret needed. If you are not sure what this is, do not check it or ask for help.">
            Is this client public?<br><em>Then only openid scope is allowed</em></span></td>
            <td><input type="checkbox" name="${clientIsPublic}" <c:out value="${clientIsPublicValue}"/> />
            </td>
        </tr>--%>

        <tr style="vertical-align: top">
            <td>Callback URLs:</td>
            <td>
                <textarea id="${callbackURI}" rows="10" cols="80"
                          name="${callbackURI}"><c:out value="${callbackURIValue}"/></textarea>
            </td>
        </tr>
        <tr style="vertical-align: top">
            <td>Scopes:</td>
            <td><c:forEach items="${scopes}" var="scope">
                    <input type="checkbox"
                           name="chkScopes"
                           value="${scope}"<c:set var="xxx" scope="session" value="${scope}"/><c:if test="${xxx == 'openid'}"> checked="checked"</c:if>>${scope}<br></c:forEach>
            </td>
        </tr>
        <tr>
            <td><input type="submit" value="submit"/></td>
        </tr>
    </table>
    <input type="hidden" id="status" name="${action}"
           value="${request}"/>

  </div> <!-- main -->
</div> <!-- wrap -->
</form>
</body>
</html>
