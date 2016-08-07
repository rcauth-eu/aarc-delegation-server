package org.delegserver.oauth2.servlet;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.HttpHeaders;
import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.DSOA2ServiceTransaction;
import org.delegserver.oauth2.generator.CertExtensionGenerator;
import org.delegserver.oauth2.generator.DNGenerator;
import org.delegserver.oauth2.generator.TraceRecordGenerator;
import org.delegserver.oauth2.shib.ShibAssertionRetriever;
import org.delegserver.oauth2.shib.ShibHeaderExtractor;
import org.delegserver.oauth2.util.JSONConverter;
import org.delegserver.storage.DSOA2Client;
import org.delegserver.storage.RDNElement;
import org.delegserver.storage.RDNElementPart;
import org.delegserver.storage.TraceRecord;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.servlet.PresentableState;

/**
 * Custom Authorization Servlet implementation (/authorize). Apart from the
 * regular authorization flow this servlet will save the attribute list released
 * by the home IdP of the authenticated user and the claims constructed from
 * them into the Service Transaction.
 * <p>
 * When the 'edu.uiuc.ncsa.myproxy.getcert' is received this servlet will create
 * a {@link TraceRecord} and a subject DN for the authenticated user.
 * <p>
 * For more details on DNs  are constructed consult the RCauth Policy Document
 * ( https://rcauth.eu/policy ) section 3.1.2 * 
 * 
 * @author "Tamás Balogh"
 * @see <a href="https://rcauth.eu/policy">https://rcauth.eu/policy</a>
 */
public class DSOA2AuthorizationServer extends ConsentAwareOA2AuthServer {

	/**
	 * JSP Variable for the consent page
	 */
	public static final String AUTH_CLAIMS_KEY = "authClaims";
	public static final String AUTH_CLIENT_DESC = "clientDesc";

	/**
	 * Special attribute name under which the user certificate DN is stored internally.
	 * Use this name in the server.cfg to map this attribute to a claim
	 */
	public static final String CERT_SUBJECT_ATTR = "X509_CERT_SUBJECT";
	
	/* OVERRIDEN METHODS */

	@Override
	public void prepare(PresentableState state) throws Throwable {
		super.prepare(state);

		AuthorizedState authorizedState = (AuthorizedState) state;
		
		if (state.getState() == AUTHORIZATION_ACTION_START) {

			DSOA2ServiceTransaction serviceTransaction = ((DSOA2ServiceTransaction) authorizedState.getTransaction());
			DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
			
			//printAllParameters(state.getRequest());

			/* DEBUG AND TRACE LOGGING */
			// initialize session specific trace logger with session identifier
			se.getTraceLogger().initSessionLogger(serviceTransaction.getIdentifierString());
			se.getTraceLogger().marked("NEW AUTHORIZE REQUEST [transaction: " + serviceTransaction.getIdentifierString() + "]");

			logAssertions(state.getRequest());
			logReferer(state.getRequest());
			logAllParameters(state.getRequest());
			
			// set user attributes
			// TODO: Should attributes be passed in headers by shibboleth? Can't we do better?
			// Update: AbstractAuthorizationServl.et hardcodes the use of headers and fails
			// if UseHeader are not enabled. Ask Jim?
			serviceTransaction.setUserAttributes(ShibHeaderExtractor.getAttrMap(state.getRequest()));

			// generate the claims from the user attributes
			generateClaims(authorizedState);
			
			// save transaction
			getTransactionStore().save(serviceTransaction);

			// set the claims as an attribute so that the consent JSP can then
			// display them
			authorizedState.getRequest().setAttribute(AUTH_CLAIMS_KEY, serviceTransaction.getClaims());
			
			// set the client description for the consent page
			DSOA2Client client = (DSOA2Client) serviceTransaction.getClient();
			authorizedState.getRequest().setAttribute(AUTH_CLIENT_DESC, client.getDescription());
			
			// destroy the session specific trace logger
			se.getTraceLogger().destroySessionLogger();
			
		} 
	}	

	/* GENERATOR METHODS */

	/**
	 * Generate user claims from attributes. Using the mapping provided in the server 
	 * configuration map SAML attributes into OpenIDConnect claims. These claims will
	 * then be saved into the current transaction
	 * 
	 * @param state The current session state
	 */
	protected void generateClaims(AuthorizedState state) {

		DSOA2ServiceTransaction serviceTransaction = ((DSOA2ServiceTransaction) state.getTransaction());

		//handle the 'edu.uiuc.ncsa.myproxy.getcert' scope in a special way 
		if ( serviceTransaction.getScopes().contains( OA2Scopes.SCOPE_MYPROXY ) ) {
			generateTraceRecord( serviceTransaction );
		}
		
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
				
					//Object value = ShibHeaderExtractor.getRequestAttrs(state.getRequest(), attribute);
					Object value = serviceTransaction.getUserAttributes().get( attribute );

					if (value != null) {
						claims.put(claim, value);
					}
				}
			}
		}

		// set claims
		serviceTransaction.setClaims(claims);		
	}
	
	/**
	 * Generate a TraceRecord from the user attributes under the current transaction. 
	 * This method will search for an already existing TraceRecord for the user or create
	 * a new one. The resulting TraceRecord, the generated user DN (saved as a custom 
	 * attribute under {@link CERT_SUBJECT_ATTR}) and the MyProxy USERNAME will be saved
	 * into the current transaction.
	 * <p>
	 * Moreover, this method also generates the final user DN which will be passed along to the
	 * MyProxy connection. Both trace record and transaction should get updates by this method.
	 * 
	 * @param trans The current transaction with user attributes 
	 */
	protected void generateTraceRecord(DSOA2ServiceTransaction trans) {

		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		DNGenerator dnGenerator = se.getDnGenerator();
		TraceRecordGenerator generator = se.getTraceRecordGenerator();
		CertExtensionGenerator certExtGenerator = se.getCertExtGenerator();
	
		// 1. GET TRACE RECORD FOR THIS TRANSACTION
		traceDebug("6.a.1  Get trace record for current transaction");
		
		TraceRecord traceRecord =  generator.generate( trans.getUserAttributes() );
		
		// by now we should already have a trace record. if not we shouldn't continue!  
		if ( traceRecord == null ) {
			throw new GeneralException("Could not create/retrieve trace record for the current transaction!");
		}

		// 3. SAVE TRACE RECORD
		traceDebug("6.a.3 Saving trace record");		
		se.getTraceRecordStore().save(traceRecord);
		
		// 4. GENERATE USER DN FOR TRANSACTION AND SAVE TRANSACTION
		traceDebug("6.a.4 Generating user DN for transaction...");		
		//the DN sufix should be taken from the trace record retrieved/created above!!!
		//if you recreate the CN at this point using DnGenerator you might end up
		//creating a new CN for an already existing user in the system.
		RDNElement orgRDN = traceRecord.getOrganization();
		RDNElement cnRDN = traceRecord.getCommonName();
		int cnRDNseqNr = traceRecord.getSequenceNr();
		
		//append the sequence number where applicable 
		if ( cnRDNseqNr > 0 ) {
			trans.setMyproxyUsername( dnGenerator.formatDNSufix( orgRDN.getElement() , cnRDN.getElement(), cnRDNseqNr ) );
		} else {
			trans.setMyproxyUsername( dnGenerator.formatDNSufix( orgRDN.getElement() , cnRDN.getElement() ) );	
		}
		
		//log the final trace record elements and their origin
		logTraceRecord(traceRecord);
		traceDebug("6.a.4 The generated user DN is: " + trans.getMyproxyUsername());		

		//complete the USERNAME parameter with extensions 
		String additionalInfo = certExtGenerator.getCertificateExtensions( trans.getUserAttributes() );

		if ( additionalInfo != null && !additionalInfo.isEmpty()) { 
			trans.setMyproxyUsername( trans.getMyproxyUsername() + " " + additionalInfo );
			traceDebug("6.a.5 Full MyProxy username: " + trans.getMyproxyUsername());
		} else {
			traceDebug("6.a.5 No extensions appended into the certificate request. Requesting cert without it");
		}

		// log the final DN (with extension) to INFO
		traceInfo("Full MyProxy username: " + trans.getMyproxyUsername());		
		
		// save the trace_recrod reference to the transaction
		// TODO: Do we need this for anything?
		trans.setTraceRecord( traceRecord.getCnHash() );
		
		// save the generated full user DN as a user attribute 
		trans.getUserAttributes().put(dnGenerator.getAttributeName() , dnGenerator.formatFullDN( orgRDN.getElement() , 
																							     cnRDN.getElement() ,
																							     cnRDNseqNr ));
		se.getTransactionStore().save(trans);	
		
	}

	/* DEBUG AND DISPLAY */

	protected void logAllParameters(HttpServletRequest request) {

		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		
		// only bother printing the individual request attributes if debug is on
		if ( se.getTraceLogger().isDebugOn() ) {
			
			String reqUrl = request.getRequestURL().toString();
			String queryString = request.getQueryString(); // d=789
			if (queryString != null) {
				reqUrl += "?" + queryString;
			}
	
			traceDebug("Request parameters for '" + reqUrl + "'");
	
			if (request.getParameterMap() == null || request.getParameterMap().isEmpty()) {
				traceDebug("  (none)");
			} else {
				for (Object key : request.getParameterMap().keySet()) {
					String[] values = request.getParameterValues(key.toString());
					if (values == null || values.length == 0) {
					} else {
	
						if (values.length == 1) {
	
							if (values[0] != null && !values[0].isEmpty()) {
								traceDebug(" " + key + " = " + values[0]);
							}
	
						} else {
							List<String> nonEmptyValues = new ArrayList<String>();
							for (String x : values) {
								if (x != null && !x.isEmpty()) {
									nonEmptyValues.add(x);
								}
							}
							if (!nonEmptyValues.isEmpty()) {
								traceDebug(
										" " + key + " = " + JSONConverter.toJSONArray(nonEmptyValues).toJSONString());
							}
						}
					}
				}
			}
	
			traceDebug("Cookies:");
			if (request.getCookies() == null) {
				traceDebug(" (none)");
			} else {
				for (javax.servlet.http.Cookie c : request.getCookies()) {
					if (c.getValue() != null && !c.getValue().isEmpty()) {
						traceDebug(" " + c.getName() + " = " + c.getValue());
					}
				}
			}
	
			traceDebug("Headers:");
			Enumeration e = request.getHeaderNames();
			if (!e.hasMoreElements()) {
				traceDebug(" (none)");
			} else {
	
				// IMPORTANT !!! Map the header parameters with the right encoding
				Charset isoCharset = Charset.forName("ISO-8859-1");
				Charset utf8Charset = Charset.forName("UTF-8");
	
				while (e.hasMoreElements()) {
					String name = e.nextElement().toString();
					String header = request.getHeader(name);
					if (header != null && !header.isEmpty()) {
	
						byte[] v = header.getBytes(isoCharset);
						traceDebug(" " + name + " = " + new String(v, utf8Charset));
					}
				}
			}
	
			traceDebug("Attributes:");
			Enumeration attr = request.getAttributeNames();
			if (!e.hasMoreElements()) {
				traceDebug(" (none)");
			} else {
				while (attr.hasMoreElements()) {
					String name = attr.nextElement().toString();
					String attribute = request.getAttribute(name).toString();
					if (attribute != null && !attribute.isEmpty()) {
						traceDebug(" " + name + " = " + attribute);
					}
				}
			}
		}
	}

	private void logReferer(HttpServletRequest request) {

		// get the referer header
		String referer = request.getHeader(HttpHeaders.REFERER);

		// in case the previous request failed, try with lowercase
		if (referer == null || referer.isEmpty()) {
			referer = request.getHeader(HttpHeaders.REFERER.toLowerCase());
		}

		// print referer to trace log
		if (referer == null || referer.isEmpty()) {
			traceDebug("There was no 'referer' header set in the request!");
		} else {
			traceInfo("Referer Header: " + referer);
		}

	}

	private void logAssertions(HttpServletRequest request) {

		try {

			String assertions = ShibAssertionRetriever.getShibAssertions(request);

			traceDebug("SAML Assertions Received :");
			traceInfo(assertions);

		} catch (Throwable e) {
			this.warn("Error Requesting Shibboleth Assertion");
			this.warn(e.getMessage());
			e.printStackTrace();
		}

	}

	public void logTraceRecord(TraceRecord traceRecord) {
		logTraceRecordElement( traceRecord.getOrganization() );
		logTraceRecordElement( traceRecord.getCommonName() );
	}
	
	public void logTraceRecordElement(RDNElement element) {
		for ( RDNElementPart rdnPart : element.getElementParts() ) {
		
			StringBuilder orgTrace = new StringBuilder();
			
			orgTrace.append("RDN : '" + rdnPart.getElement() + "' ");
			orgTrace.append("(" + rdnPart.getElementSource() + " = ");
			orgTrace.append("'" + rdnPart.getElementOrig() + "')");

			
			traceInfo(orgTrace.toString());
		}
	}
	
	public void traceInfo(String x) {
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		se.getTraceLogger().info(x);
	}
	
	public void traceDebug(String x) {
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		se.getTraceLogger().debug(x);
	}
	
	public void traceError(String x) {
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		se.getTraceLogger().error(x);
	}
	
	public void traceWarn(String x) {
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		se.getTraceLogger().warn(x);
	}		

}
