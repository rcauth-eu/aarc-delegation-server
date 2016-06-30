package org.delegserver.oauth2.servlet;

import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.http.HttpHeaders;
import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.DSOA2ServiceTransaction;
import org.delegserver.oauth2.shib.ShibAssertionRetriever;
import org.delegserver.oauth2.shib.ShibHeaderExtractor;
import org.delegserver.oauth2.util.HashingUtils;
import org.delegserver.oauth2.util.JSONConverter;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.servlet.PresentableState;

/**
 * Custom Authorization Servlet implementation (/authorize). Apart from the
 * regular authorization flow this servlet will save the attribute list released
 * by the home IdP of the authenticated user and the claims constructed from
 * them into the Service Transaction.
 * 
 * @author "Tamás Balogh"
 *
 */
public class DSOA2AuthorizationServer extends OA2AuthorizationServer {

	/* POSTPROCESS AUTHORIZED STATE */

	/**
	 * Prefix the consent remembering cookie with a static value
	 */
	public static String OA4MP_CONSENT_COOKIE_NAME_PREFIX = "consent_";
	/**
	 * The value of the consent remembering cookie
	 */
	public static String OA4MP_CONSENT_COOKIE_VALUE = "true";
	/**
	 * The age of the consent remembering cookie
	 */
	public static int OA4MP_CONSENT_COOKIE_MAX_AGE = 90;

	public static String AUTH_CLAIMS_KEY = "auth_claims";

	public static String AUTHORIZE_ENDPOINT = "/authorize";
	public static String REMOTE_USER_REDIRECT_PAGE = "/authorize-remote-user-redirect.jsp";

	@Override
	public void present(PresentableState state) throws Throwable {

		AuthorizedState aState = (AuthorizedState) state;
		postprocess(new TransactionState(state.getRequest(), aState.getResponse(), null, aState.getTransaction()));

		switch (aState.getState()) {
		case AUTHORIZATION_ACTION_START:

			String userName = getRemoteUser(aState);

			// saving the username 
			aState.getTransaction().setUsername(userName);
			info("*** storing user name = " + userName);
			getTransactionStore().save(aState.getTransaction());

			String masterPortalID = ((ServiceTransaction) aState.getTransaction()).getClient().getIdentifier().toString();
			String hashedID = HashingUtils.getInstance().hashToHEX(masterPortalID + userName);

			// retrieve the consent remembering cookie
			String consentCookie = getCookie(aState.getRequest(), OA4MP_CONSENT_COOKIE_NAME_PREFIX + hashedID);
			
			// check if the cookie is valid
			if (consentCookie != null && consentCookie.equals(OA4MP_CONSENT_COOKIE_VALUE)) {

				debug("Consent cookie found! Automatically redirecting user without the consent page");
				
				// Forward the user to an automatic redirect page. In case javascript is disabled the user
				// will have to manually click the redirect button.
				
				// Note: A custom redirecting JSP form is needed here because calling dispatcher.forward()
				// will create a loop by restarting the authorization session in OA2AuthorizationServer
				// at line 108. Checking for a new session is currently done by looking at the RESPONSE_TYPE
				// parameter from the request. An additional check for the 'action=ok' parameter would
				// stop the session from being restarted.
				
				JSPUtil.fwd(aState.getRequest(), aState.getResponse(), REMOTE_USER_REDIRECT_PAGE);

			} else {

				debug("No consent cookie found! Showing consent page");
				
				aState.getRequest().setAttribute(AUTHORIZATION_USER_NAME_VALUE, escapeHtml(userName));
				
				JSPUtil.fwd(state.getRequest(), state.getResponse(), REMOTE_USER_INITIAL_PAGE);
				info("3.a. User information obtained for grant = " + aState.getTransaction().getAuthorizationGrant());

			}
			break;

		case AUTHORIZATION_ACTION_OK:

			JSPUtil.fwd(state.getRequest(), state.getResponse(), OK_PAGE);
			break;

		default:
			// fall through and do nothing
			debug("Hit default case in AbstractAuthZ servlet");
		}
	}

	@Override
	public void prepare(PresentableState state) throws Throwable {
		super.prepare(state);

		setConsentCookie((AuthorizedState) state);

		// only do something if the user has already been authorized and gave consent
		if (state.getState() == AUTHORIZATION_ACTION_START) {

			AuthorizedState authorizedState = (AuthorizedState) state;
			DSOA2ServiceTransaction serviceTransaction = ((DSOA2ServiceTransaction) authorizedState.getTransaction());
			DSOA2ServiceEnvironment env = (DSOA2ServiceEnvironment) environment;

			printAllParameters(authorizedState.getRequest());

			/* DEBUG AND TRACE LOGGING */
			// initialize session specific trace logger with session identifier
			env.getTraceLogger().initSessionLogger(serviceTransaction.getIdentifierString());
			env.getTraceLogger()
					.marked("NEW AUTHORIZE REQUEST [transaction: " + serviceTransaction.getIdentifierString() + "]");

			logAssertions(authorizedState.getRequest());
			logReferer(authorizedState.getRequest());
			// only bother printing the individual request attributes if debug is on
			if (env.getTraceLogger().isDebugOn()) {
				logAllParameters(authorizedState.getRequest());
			}

			// destroy the session specific trace logger
			env.getTraceLogger().destroySessionLogger();

			/* CLAIMS */

			// build a claim map based in the incoming scope set in the
			// transaction and the attributes given in the request
			Map<String, Object> claims = new HashMap<String, Object>();

			// iterate through the list of accepted scopes sent by the client
			for (String scope : serviceTransaction.getScopes()) {

				// get the configuration claimMap in order to decide which
				// claims to extract for this specific scope
				Map<String, String> claimMap = ((DSOA2ServiceEnvironment) getServiceEnvironment()).getClaimsMap(scope);

				if (claimMap != null) {
					// we need to add some claims
					for (String claim : claimMap.keySet()) {

						// extract mapped attribute from the request object
						String attribute = claimMap.get(claim);
						Object value = ShibHeaderExtractor.getRequestAttrs(state.getRequest(), attribute);

						if (value != null) {
							claims.put(claim, value);
						}
					}
				}
			}

			// set claims
			serviceTransaction.setClaims(claims);
			// set user attributes
			// TODO: Should attributes be passed in headers by shibboleth? Can't we do better?
			// Update: AbstractAuthorizationServl.et hardcodes the use of headers and fails
			// if UseHeader are not enabled. Ask Jim?
			serviceTransaction.setUserAttributes(ShibHeaderExtractor.getAttrMap(state.getRequest()));

			// save transaction
			getTransactionStore().save(serviceTransaction);

			// set the claims as an attribute so that the consent JSP can then
			// display them
			authorizedState.getRequest().setAttribute(AUTH_CLAIMS_KEY, claims);
		}
	}

	/* HELPER METHODS */

	/**
	 * Set a consent remembering cookie in the response object of the current session.
	 * The consent cookie is a composed of the hash of the Master Portal client ID
	 * and the authenticated user 'sub'. 
	 * 
	 * @param state The current session state
	 */
	protected void setConsentCookie(AuthorizedState state)  {

		// only execute this if user consent has been given and authorization
		// was ok
		if (getState(state.getRequest()) == AUTHORIZATION_ACTION_OK) {

			// get the checkbox value to see if we have to remember the consent
			String rememberConsent = state.getRequest().getParameter("remember");

			if (rememberConsent != null && rememberConsent.equals("on")) {

				// get the Master Portal client ID that we are talking to in this session
				String masterPortalID = ((ServiceTransaction) state.getTransaction()).getClient().getIdentifier().toString();
				String userName = getRemoteUser(state);

				// Note: be aware of the right encoding for cookies! Values such as '=' do not play nicely
				// so use HEX representation of the hash rather then the base64

				// get the HEX encoded hash of the client ID
				String hashedID = HashingUtils.getInstance().hashToHEX(masterPortalID + userName);

				// create a new response cookie
				Cookie consentCookie = new Cookie(OA4MP_CONSENT_COOKIE_NAME_PREFIX + hashedID,
						OA4MP_CONSENT_COOKIE_VALUE);
				consentCookie.setMaxAge(OA4MP_CONSENT_COOKIE_MAX_AGE * 24 * 60 * 60);
				consentCookie.setPath(state.getRequest().getContextPath() + AUTHORIZE_ENDPOINT);

				debug("Setting the consent remembering cookie " + consentCookie.getValue());
				
				// add the cookie to the response
				state.getResponse().addCookie(consentCookie);

			}
		}
	}

	/**
	 * Retrieve a cookie value from the request object by its name. If there is no
	 * cookie found with cookieName, return null
	 * 
	 * @param request The current request object 
	 * @param cookieName The name of the cookie
	 * @return The value of the cookie
	 */
	public static String getCookie(HttpServletRequest request, String cookieName) {

		for (Cookie cookie : request.getCookies()) {

			if (cookie.getName().equals(cookieName)) {
				return cookie.getValue();
			}

		}
		return null;

	}

	/**
	 * Return the authenticated users' user name / identifier sent by Shibboleth.
	 * <p>
	 * Only Shibboleth headers are supported at the moment. This method will try different
	 * alternatives to retrieve the username, including the REMOT_USER header.  
	 * 
	 * @param aState The current session state
	 * @return The remote users' name
	 */
	public String getRemoteUser(AuthorizedState aState) {

        if (getServiceEnvironment().getAuthorizationServletConfig().isUseHeader()) {

            info("*** PRESENT: Use headers enabled.");
            String x = null;
            
            if (getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName().equals("REMOTE_USER")) {
                // slightly more surefire way to get this.
                x = aState.getRequest().getRemoteUser();
                info("*** got user name from request = " + x);
            } else {
                x = aState.getRequest().getHeader(getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName());
                info("Got username from header \"" + getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName() + "\" + directly: " + x);
            }

            if (isEmpty(x)) {
                if (getServiceEnvironment().getAuthorizationServletConfig().isRequireHeader()) {
                    throw new GeneralException("Error: configuration required using the header \"" +
                            getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName() + "\" " +
                            "but this was not set. Cannot continue."
                    );
                }
                // not required, it is null

            } else {
                return x;
            }
        } else {
            info("*** PRESENT: Use headers DISABLED.");
        }
        
		return null;
        
	}

	/* DEBUG AND DISPLAY */

	protected void logAllParameters(HttpServletRequest request) {

		DSOA2ServiceEnvironment env = (DSOA2ServiceEnvironment) environment;
		Logable traceLogger = env.getTraceLogger();

		String reqUrl = request.getRequestURL().toString();
		String queryString = request.getQueryString(); // d=789
		if (queryString != null) {
			reqUrl += "?" + queryString;
		}

		traceLogger.debug("Request parameters for '" + reqUrl + "'");

		if (request.getParameterMap() == null || request.getParameterMap().isEmpty()) {
			traceLogger.debug("  (none)");
		} else {
			for (Object key : request.getParameterMap().keySet()) {
				String[] values = request.getParameterValues(key.toString());
				if (values == null || values.length == 0) {
				} else {

					if (values.length == 1) {

						if (values[0] != null && !values[0].isEmpty()) {
							traceLogger.debug(" " + key + " = " + values[0]);
						}

					} else {
						List<String> nonEmptyValues = new ArrayList<String>();
						for (String x : values) {
							if (x != null && !x.isEmpty()) {
								nonEmptyValues.add(x);
							}
						}
						if (!nonEmptyValues.isEmpty()) {
							traceLogger.debug(
									" " + key + " = " + JSONConverter.toJSONArray(nonEmptyValues).toJSONString());
						}
					}
				}
			}
		}

		traceLogger.debug("Cookies:");
		if (request.getCookies() == null) {
			traceLogger.debug(" (none)");
		} else {
			for (javax.servlet.http.Cookie c : request.getCookies()) {
				if (c.getValue() != null && !c.getValue().isEmpty()) {
					traceLogger.debug(" " + c.getName() + " = " + c.getValue());
				}
			}
		}

		traceLogger.debug("Headers:");
		Enumeration e = request.getHeaderNames();
		if (!e.hasMoreElements()) {
			traceLogger.debug(" (none)");
		} else {

			// IMPORTANT !!! Map the header parameters with the right encoding
			Charset isoCharset = Charset.forName("ISO-8859-1");
			Charset utf8Charset = Charset.forName("UTF-8");

			while (e.hasMoreElements()) {
				String name = e.nextElement().toString();
				String header = request.getHeader(name);
				if (header != null && !header.isEmpty()) {

					byte[] v = header.getBytes(isoCharset);
					traceLogger.debug(" " + name + " = " + new String(v, utf8Charset));
				}
			}
		}

		traceLogger.debug("Attributes:");
		Enumeration attr = request.getAttributeNames();
		if (!e.hasMoreElements()) {
			traceLogger.debug(" (none)");
		} else {
			while (attr.hasMoreElements()) {
				String name = attr.nextElement().toString();
				String attribute = request.getAttribute(name).toString();
				if (attribute != null && !attribute.isEmpty()) {
					traceLogger.debug(" " + name + " = " + attribute);
				}
			}
		}

	}

	private void logReferer(HttpServletRequest request) {

		// get the trace logger
		DSOA2ServiceEnvironment env = (DSOA2ServiceEnvironment) environment;
		Logable traceLogger = env.getTraceLogger();

		// get the referer header
		String referer = request.getHeader(HttpHeaders.REFERER);

		// in case the previous request failed, try with lowercase
		if (referer == null || referer.isEmpty()) {
			referer = request.getHeader(HttpHeaders.REFERER.toLowerCase());
		}

		// print referer to trace log
		if (referer == null || referer.isEmpty()) {
			traceLogger.warn("There was no 'referer' header set in the request!");
		} else {
			traceLogger.info("Referer Header: " + referer);
		}

	}

	private void logAssertions(HttpServletRequest request) {

		// get the trace logger
		DSOA2ServiceEnvironment env = (DSOA2ServiceEnvironment) environment;
		Logable traceLogger = env.getTraceLogger();

		try {

			String assertions = ShibAssertionRetriever.getShibAssertions(request);

			traceLogger.debug("SAML Assertions Received :");
			traceLogger.info(assertions);

		} catch (Throwable e) {
			this.warn("Error Requesting Shibboleth Assertion");
			this.warn(e.getMessage());
			e.printStackTrace();
		}

	}

}
