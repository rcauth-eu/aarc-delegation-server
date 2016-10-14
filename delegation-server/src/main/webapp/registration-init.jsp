<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<html>

<head>
    <title>RCAuth Delegation Service (Online CA) Client Registration Page</title>
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
    <h2>Welcome to the RCAuth Client Registration Page</h2>

    <p>This page allows you to register your client with the
        MyProxy delegation service that supports the OIDC/OAuth 2. To get your client approved,
        please fill out the form below. Your request will be evaluated for approval. For more information,
        please make sure you read the
        <a href="http://grid.ncsa.illinois.edu/myproxy/oauth/client/manuals/registering-with-an-oauth2-server.xhtml"
           target="_blank">Registering a Client with an OAuth 2 server</a> document.
    </p><br>
    <table>
        <tr>
            <td>Client Name:</td>
            <td><input type="text" size="25" name="${clientName}" value="${clientNameValue}"/></td>
        </tr>

        <tr style="vertical-align: top">
            <td>Client Description:</td>
            <td>
                <textarea id="${clientDescription}" rows="10" cols="80"
                          name="${clientDescription}">${clientDescriptionValue}</textarea>
            </td>
        </tr>

        <tr>
            <td>Contact email:</td>
            <td><input type="text" size="25" name="${clientEmail}" value="${clientEmailValue}"/></td>
        </tr>
        <tr>
            <td>Home URL:</td>
            <td><input type="text" size="25" name="${clientHomeUrl}" value="${clientHomeUrlValue}"/></td>
        </tr>

        <tr>
            <td ${rtFieldVisible}>Refresh Token lifetime:</td>
            <td ${rtFieldVisible}><input type="text" size="25" name="${rtLifetime}" value="${rtLifetimeValue}"/>(in seconds - leave blank for no refresh tokens.)</td>
        </tr>
        <tr>
            <td></td>
            <td><input type="hidden" name="${clientProxyLimited}" ${clientProxyLimitedValue} />
            </td>
        </tr>


        <tr style="vertical-align: top">
            <td>Callback URLs:</td>
            <td>
                <textarea id="${callbackURI}" rows="10" cols="80"
                          name="${callbackURI}">${callbackURIValue}</textarea>
            </td>
        </tr>
        <tr>
            <td><input type="submit" value="submit"/></td>
        </tr>
        <tr>
            <td colspan="2"><b><font color="red">${retryMessage}</font></b></td>
        </tr>
    </table>
    <input type="hidden" id="status" name="${action}"
           value="${request}"/>

  </div> <!-- main -->
</div> <!-- wrap -->
</form>
</body>
</html>
