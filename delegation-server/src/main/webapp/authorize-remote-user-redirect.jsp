<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<html>

<head>
    <title>RCAuth Online CA</title>
    <link rel="stylesheet" type="text/css" href="default.css" />
    <link rel="stylesheet" type="text/css" href="rcauth.css" />

    <script>
    
    function autoSubmit()  {

    	// only redirect autmatically if request succeeded without an error
    	// this is needed to prevent infinately redirecting error loops
    	if ( ! "${retryMessage}" ) {
	
    		document.getElementById("showRedirectWait").style.display = "inline";
			document.title = 'Loading...';
			document.getElementById("submitForm").submit();
  
    	} 
    }
    
    </script>

</head>

<body id="mainBody" onload="autoSubmit('${show_consent}')">
<div id="wrap">

<div id="showRedirectWait" style="display: none">
<h1>Redirecting to Master Portal "${clientName}"...</h1>
<h2>this might take a few seconds, please wait</h2>
</div>


<c:if test="${not empty retryMessage}">
<div id="retryError">
<h3>${retryMessage}<BR>Could not connect to online CA. Please retry.</h3><p>
</div>
</c:if>


<noscript>
<div id="manualRedirect">

<div id="logoHolder">
    <div class="topLeft">
        <div id="topLogo" class="topLogo"><img src="RCauth-eu-logo-150.gif"><br/></div>
        <div id="topText" class="topText">The white-label Research and Collaboration Authentication CA Service for Europe</div>				
    </div>
</div>
<div class="clear"></div>

<h2>RCauth.eu Online CA Redirect Page</h2>
<p>
Looks like you have disabled JavaScript in your browser! Please click on the following button to get redirected to
the next page. 
<p>

</div> <!-- manualRedirect -->
</noscript>

<form id="submitForm" action="${actionToTake}" method="POST">

	<noscript>
    	<input type="submit" style="float: left;" value="Redirect"/>
	</noscript>
	
    <input type="hidden" id="status" name="${action}" value="${actionOk}"/>
    <input type="hidden" id="token" name="${tokenKey}" value="${authorizationGrant}"/>
    <input type="hidden" id="state" name="${stateKey}" value="${authorizationState}"/>

</form>

</div> <!-- wrap -->
</body>
</html>
