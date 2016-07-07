package org.delegserver.oauth2.servlet;

import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.delegserver.oauth2.shib.ShibHeaderExtractor;
import org.delegserver.oauth2.util.HashingUtils;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.servlet.PresentableState;

/**
 * Wrapper around the authorization server implementing consent 
 * remembering via browser cookies. The browser cookie is created 
 * by hashing the Master Portal ID together with the username to
 * assure unique per Master Portal per use cookies.
 * <p>
 * When the consent cookie is encountered, this servlet automatically
 * redirect you to the next step in the protocol without showing the
 * consent page.
 * 
 * @author "Tamás Balogh"
 *
 */
public class ConsentAwareOA2AuthServer extends OA2AuthorizationServer {

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

	/**
	 *  Endpoints
	 */
	public static String AUTHORIZE_ENDPOINT = "/authorize";
	public static String REMOTE_USER_REDIRECT_PAGE = "/authorize-remote-user-redirect.jsp";

	
	/* OVERRIDEN METHODS */

	@Override
	public void prepare(PresentableState state) throws Throwable {
		super.prepare(state);

		AuthorizedState authorizedState = (AuthorizedState) state;
			
		if (state.getState() == AUTHORIZATION_ACTION_OK) {
			
			// set the consent cookie so that next time around we don't have to show the page
			setConsentCookie(authorizedState);
			
		}
	}	
	
	@Override
	public void present(PresentableState state) throws Throwable {

		AuthorizedState aState = (AuthorizedState) state;
		postprocess(new TransactionState(state.getRequest(), aState.getResponse(), null, aState.getTransaction()));

		switch (aState.getState()) {
		case AUTHORIZATION_ACTION_START:

			String username = null;
			
			if (getServiceEnvironment().getAuthorizationServletConfig().isUseHeader()) {
				username = ShibHeaderExtractor.getRemoteUser(aState.getRequest() , 
															 getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName());
			}
			
			if (isEmpty(username)) {
                if (getServiceEnvironment().getAuthorizationServletConfig().isRequireHeader()) {
                    throw new GeneralException("Error: configuration required using the header \"" +
                            getServiceEnvironment().getAuthorizationServletConfig().getHeaderFieldName() + "\" " +
                            "but this was not set. Cannot continue."
                    );
                }
                
                throw new GeneralException("Unable to extact REMOTE_USER from the current authorization session!");
            }

			// saving the username 
			aState.getTransaction().setUsername(username);
			info("*** storing user name = " + username);
			getTransactionStore().save(aState.getTransaction());

			if ( ! checkConsentCookie(aState) ) {

				debug("No consent cookie found! Showing consent page");
				
				aState.getRequest().setAttribute(AUTHORIZATION_USER_NAME_VALUE, escapeHtml(username));
				
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
	
	/* CONSENT COOKIE HANDLING */
	
	/**
	 * Set a consent remembering cookie in the response object of the current session.
	 * The consent cookie is a composed of the hash of the Master Portal client ID
	 * and the authenticated user 'sub'. 
	 * 
	 * @param state The current session state
	 */
	protected void setConsentCookie(AuthorizedState state)  {

		// get the checkbox value to see if we have to remember the consent
		String rememberConsent = state.getRequest().getParameter("remember");

		if (rememberConsent != null && rememberConsent.equals("on")) {

			// get the Master Portal client ID that we are talking to in this session
			String masterPortalID = state.getTransaction().getClient().getIdentifier().toString();
			String userName = state.getTransaction().getUsername();

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
	
	/**
	 * Check the existence of a valid consent cookie in the current request. In case a valid
	 * consent cookie is found user an automatically redirecting page instead of showing
	 * the consent page again. 
	 * 
	 * @param state The current session state
	 * @return true if a valid consent cookie was found, false otherwise
	 * @throws IOException In case of redirect failures
	 * @throws ServletException In case of redirect failures
	 */
	protected boolean checkConsentCookie(AuthorizedState state) throws IOException, ServletException {
		
		String userName = state.getTransaction().getUsername();
		String masterPortalID = state.getTransaction().getClient().getIdentifier().toString();
		String hashedID = HashingUtils.getInstance().hashToHEX(masterPortalID + userName);

		// retrieve the consent remembering cookie
		String consentCookie = getCookie(state.getRequest(), OA4MP_CONSENT_COOKIE_NAME_PREFIX + hashedID);
		
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
			
			JSPUtil.fwd(state.getRequest(), state.getResponse(), REMOTE_USER_REDIRECT_PAGE);

			return true;
			
		} 
		
		return false;
		
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
	
}
