<%--
  User: Jeff Gaynor
  Date: 9/25/11
  Time: 6:42 PM
  Properties supplied:
  * clientName = the name of the client
  * clientHome = the home uri of the client
  * AuthUserName = field name containing the user name on submission
  * AuthPassword = field name containing the user's password on submission
  * retryMessage = message displayed if the login in fails.
  * tokenKey = name of hidden field to pass along the authorizationGrant
  * actionToTake = what action that submitting the form invokes.
  * authorizationGrant = the identifier for this transaction
  * action = name of field containing the action the servlet should take
  * actionOk = content of action field in this case telling the service to continue processing.

--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<html>

<head>
    <title>RCAuth Online CA</title>
    <link rel="stylesheet" type="text/css" href="default.css" />
    <link rel="stylesheet" type="text/css" href="rcauth.css" />
</head>

<body id="mainBody" >

<div id="wrap">
<div id="logoHolder">
    <div class="topLeft">
        <div id="topLogo" class="topLogo"><img src="RCauth-eu-logo-150.gif"><br/></div>
        <div id="topText" class="topText">The white-label Research and Collaboration Authentication CA Service for Europe</div>
    </div>
</div>
<div class="clear"></div>

<h2>RCauth.eu Online CA consent page</h2>

<c:if test="${not empty retryMessage}">
<div id="retryError">
<h3>${retryMessage}<BR>Could not connect to online CA. Please retry.</h3><p>
</div>
</c:if>


<p>
The Master Portal below is requesting access to your personal information and
to act on your behalf.
<p>
If you approve, please accept, otherwise, cancel.
<p>
Details on which attributes are released, why, to whom, and how they are
processed can be found in the <A href="https://rcauth.eu/privacy">RCauth Pilot
ICA G1 CA privacy policy</A>.<br>
For further information on the CA see the
<A href="https://rcauth.eu/">RCauth.eu homepage</A>.

<!--form id="submitForm" action="${actionToTake}" method="POST" onsubmit="setCookie('${consent_cookie_name}','${consent_cookie_value}',90)"-->
<form id="submitForm" action="${actionToTake}" method="POST">
    <!-- Unhide this when you want to support it. All the machinery is in place.
                     <tr>
                        <td>Refresh token lifetime</td>
                        <td><input type="text" size="25" name="${AuthRTL}"
                                   value="${rtLifetime}"/></td>
                    </tr>
                    -->

    <!-- Close sign in table -->
    <input type="hidden" id="status" name="${action}"
           value="${actionOk}"/>
    <input type="hidden" id="token" name="${tokenKey}" value="${authorizationGrant}"/>
    <input type="hidden" id="state" name="${stateKey}" value="${authorizationState}"/>

    <input type="checkbox" name="remember" id="remember" checked="on"/>
    Remember

    <p>
    <p>

    <input type="submit" style="float: left;" value="Yes, continue"/>
</form>
<form action="https://rcauth.eu/noconsent/" method="POST">
    <input type="submit" style="margin-left: 1.5em;" name="cancel" value="No, cancel"/>
</form>

<br>

<h4>Master Portal Information:</h4>
<table>
    <tr style="height: 2.0em;"><td><i style="margin-right: 1.5em;">Name:</i><td><c:out value="${clientName}"/></tr>
    <tr style="height: 2.0em;  vertical-align: top"><td><i style="margin-right: 1.5em;">Description:</i><td><c:out value="${clientDesc}"/></tr>
    <tr style="height: 2.0em;"><td><i style="margin-right: 1.5em;">URL:</i><td><c:out value="${clientHome}"/></tr>
</table>


<h4>Information that will be sent to the Master Portal:</h4>

<table>
    <tr style="height: 2.0em;">
        <td><i style="margin-right: 1.5em;">sub :</i>
        <td>${userName}
    </tr>

<c:forEach items="${authClaims}" var="claim">
    <tr style="height: 2.0em;">
        <td><i style="margin-right: 1.5em;">${claim.key} :</i>
        <td>${claim.value}
    </tr>
</c:forEach>
</table>

</div> <!-- wrap -->

</body>
</html>
