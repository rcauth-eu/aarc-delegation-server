package org.delegserver.oauth2.servlet;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;

import org.apache.http.HttpHeaders;
import org.apache.http.util.ByteArrayBuffer;
import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.DSOA2ServiceTransaction;
import org.delegserver.oauth2.util.JSONConverter;
import org.delegserver.oauth2.util.ShibAttrParser;
import org.delegserver.oauth2.util.UnverifiedConnectionFactory;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.servlet.PresentableState;

/**
 * Custom Authorization Servlet implementation (/authorize). Apart from the regular authorization
 * flow this servlet will save the attribute list released by the home IdP of the authenticated
 * user and the claims constructed from them into the Service Transaction. 
 * 
 * @author "Tamás Balogh"
 *
 */
public class DSOA2AuthorizationServer extends OA2AuthorizationServer {
	
	/* POSTPROCESS AUTHORIZED STATE */
	
	@Override
	public void prepare(PresentableState state) throws Throwable {
		super.prepare(state);
		
		// only do something if the user has already been authorized and gave consent
        if (state.getState() == AUTHORIZATION_ACTION_OK) {
        	
        	AuthorizedState authorizedState = (AuthorizedState) state;
        	DSOA2ServiceTransaction serviceTransaction = ((DSOA2ServiceTransaction) authorizedState.getTransaction());
        	DSOA2ServiceEnvironment env =  (DSOA2ServiceEnvironment) environment;
        	
        	printAllParameters( authorizedState.getRequest() );
        	
        	/* DEBUG AND TRACE LOGGING*/
        	// initialize session specific trace logger with session identifier
        	env.getTraceLogger().initSessionLogger( serviceTransaction.getIdentifierString() );
        	env.getTraceLogger().marked("NEW AUTHORIZE REQUEST [transaction: " + serviceTransaction.getIdentifierString()  +"]");
        	
        	logAssertions( authorizedState.getRequest() );
        	logReferer( authorizedState.getRequest() );
        	// only bother printing the individual request attributes if debug is on
        	if ( env.getTraceLogger().isDebugOn() ) {
        		logAllParameters( authorizedState.getRequest() );
        	}
        	
        	
        	// destroy the session specific trace logger
        	env.getTraceLogger().destroySessionLogger();
        	
    		//build a claim map based in the incoming scope set in the transaction and the attributes given in the request
    		Map<String,Object> claims = new HashMap<String,Object>();
    		
    		//iterate through the list of accepted scopes sent by the client
    		for (String scope : serviceTransaction.getScopes()) {
    			
    			//get the configuration claimMap in order to decide which claims to extract for this specific scope
    			Map <String,String> claimMap = ((DSOA2ServiceEnvironment)getServiceEnvironment()).getClaimsMap(scope);
    			
    			if ( claimMap != null ) {
    				// we need to add some claims
    				for ( String claim : claimMap.keySet() ) {
    					
    					// extract mapped attribute from the request object
    					String attribute = claimMap.get(claim);
    					Object value = getRequestParam(state.getRequest(), attribute);
    					
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
    		//       Update: AbstractAuthorizationServl.et hardcodes the use of headers and fails 
    		//               if UseHeader are not enabled. Ask Jim?
        	serviceTransaction.setUserAttributes( getHeaderMap(state.getRequest()) );

        	// save transaction
    		getTransactionStore().save(serviceTransaction);
        	
        }
	}
	
	/* EXTACTING PARAMETERS FORM REQUEST */

	/**
	 * Construct a map based on the variables contained in the request header. 
	 * <p>
	 * Filter duplicate header values delimited by {@link SHIB_MULTI_VAL_DELIMITED}.
	 * 
	 * @param request Incoming request
	 * @return Map created from the headers in the request 
	 */
	protected Map<String,Object> getHeaderMap(HttpServletRequest request) {
		
		Map<String,Object> map = new HashMap<String,Object>();
		
		// iterate over headers 
        Enumeration e = request.getHeaderNames();
        while (e.hasMoreElements()) {
        	
        	String name = e.nextElement().toString();
        	
        	// convert into the right encoding
            String header = converHeader( request.getHeader(name) );
            
            if ( header != null && ! header.isEmpty() ) {
            
	            String[] values = ShibAttrParser.parseMultiValuedAttr(header);
	            
	            if ( values.length == 1 ) {
	            	map.put(name , values[0]);
	            } else {
	            	map.put(name , Arrays.asList(values));
	            }
	            
            }
        }
		
		return map;
	}
	
	/**
	 * Account for the encoding of the request headers (ISO-8859-1) and convert it to UTF-8
	 * @param value Header value in ISO-8859-1 encoding 
	 * @return Header value in UTF-8 encoding
	 */
	protected String converHeader(String value) {
		// IMPORTANT !!! Map the header parameters with the right encoding 
		Charset isoCharset = Charset.forName("ISO-8859-1");
		Charset utf8Charset = Charset.forName("UTF-8");		
		
        byte[] v = value.getBytes(isoCharset);
        return new String(v,utf8Charset);
	}

	
	/**
	 * It searches the request object for the requested key. It uses the following order of preference:
	 * PARAMETERS, ATTRIBUTES, HEADERS.
	 * <p>
	 * It either returns a single value found, or a {@link List} of {@link String}s in case of multi-valued 
	 * attributes. 
	 * 
	 * @param request Incoming request
	 * @param key The key to find in the request
	 * @return the value[s] of the requested key parameter 
	 */
    protected Object getRequestParam(HttpServletRequest request, String key) {
             
        /* check key between request PARAMETER */
    	
        String[] param = request.getParameterValues(key);
        if ( param != null && param.length != 0 ) {
        	
        	// make a distinction between single valued and multi valued parameters
        	if ( param.length == 1 ) { 
        		return param[0];
        	} else {
        		return Arrays.asList(param);
        	}
        	
        	// Alternatively you van also use the 'parseMultiValue', but be aware that 
        	// this will split individual parameters further according to the 
        	// SHIB_MULTI_VAL_DELIMITED. This might result in undesired splits in 
        	// parameter values which contain SHIB_MULTI_VAL_DELIMITED, but are not an
        	// actual shibboleth parameter.
        	
        	//return parseMultiValue( Arrays.asList(param) );
        }
        
        /* check key between request ATTRIBUTES */
        
        // multi-values ATTRIBUTES, not sure.....
        Object o = request.getAttribute(key);
        if (o != null) {
        	return o.toString();
        }
    
        /* check key between request HEADER */
        
        Enumeration<String> header = request.getHeaders(key);
        List<String> headerValues = new ArrayList<String>();
		
        if ( header != null && header.hasMoreElements() ) {
        	String value = header.nextElement().toString();
            // convert into the right encoding 
        	value = converHeader(value);
        	
        	if ( value != null && ! value.isEmpty() ) {
	            String[] values = ShibAttrParser.parseMultiValuedAttr( value );
	            
	            if (  values != null ) {
	            	headerValues.addAll( Arrays.asList(values) );
	            }
        	}
        }
        if ( ! headerValues.isEmpty() ) {
        	if ( headerValues.size() == 1 ) {
        		return headerValues.get(0);
        	} else {
        		return headerValues;
        	}
        }
        
        /* GIVE UP */
        
        return null;
    }
    
    /* DEBUG AND DISPLAY */
	
	protected void logAllParameters(HttpServletRequest request) {
		
    	DSOA2ServiceEnvironment env =  (DSOA2ServiceEnvironment) environment;
    	Logable traceLogger = env.getTraceLogger(); 
		
		String reqUrl = request.getRequestURL().toString();
        String queryString = request.getQueryString();   // d=789
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
                	
                	if ( values.length == 1 ) {
                		
                		if ( values[0] != null && ! values[0].isEmpty() ) {
                			traceLogger.debug(" " + key + " = " + values[0]);
                		}
                		
                	} else {
	                	List<String> nonEmptyValues = new ArrayList<String>();
	                	for (String x : values) {
	                		if ( x != null && ! x.isEmpty() ) {
	                			nonEmptyValues.add(x);
	                		}
	                    }
	                	if ( ! nonEmptyValues.isEmpty() ) {
	                		traceLogger.debug(" " + key + " = " + JSONConverter.toJSONArray(nonEmptyValues).toJSONString());
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
            	if ( c.getValue() != null && ! c.getValue().isEmpty() ) {
            		traceLogger.debug(" " + c.getName() + " = " + c.getValue());
            	}
            }
        }
        
        traceLogger.debug("Headers:");
        Enumeration e = request.getHeaderNames();
        if (!e.hasMoreElements()) {
        	traceLogger.debug(" (none)");
        } else {
            while (e.hasMoreElements()) {
                String name = e.nextElement().toString();
                String header = request.getHeader(name);
                if ( header != null && ! header.isEmpty() ) {
                	traceLogger.debug(" " + name + " = " + converHeader(header) );
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
                if ( attribute != null && ! attribute.isEmpty() ) {
                	traceLogger.debug(" " + name + " = " + attribute );
                }                
            }
        }
        
	}
	
	
	private void logReferer(HttpServletRequest request) {
		
		// get the trace logger
    	DSOA2ServiceEnvironment env =  (DSOA2ServiceEnvironment) environment;
    	Logable traceLogger = env.getTraceLogger();
		
    	// get the referer header
		String referer = request.getHeader(HttpHeaders.REFERER);
		
		// in case the previous request failed, try with lowercase
		if ( referer == null || referer.isEmpty() ) {
			referer = request.getHeader( HttpHeaders.REFERER.toLowerCase() );
		}
		
		// print referer to trace log
		if ( referer == null || referer.isEmpty() ) {
			traceLogger.warn("The was not 'referer' header set in the request!");
		} else {
			traceLogger.info("Referer Header: " + referer);
		}
		
	}
	
	public static String SHIB_ASSERTION_COUNT="Shib-Assertion-Count";
	public static String SHIB_ASSERTION="Shib-Assertion-";

	/**
	 * Log the SAML Assertions belonging to the current request into the transaction logs.
	 * This method will create an {@link UnverifiedConnectionFactory} to the Shibboleth SP
	 * running on 'localhost' to ask for the SAML Assertions via the {@link SHIB_ASSERTION} 
	 * links set in the request header.
	 *  
	 * @param request The original request
	 */
	private void logAssertions(HttpServletRequest request) {
	
		try {
			
			// create the factory for upcoming unverified connections
			// we cannot verify the https connections made to the Shibboleth SP because the called url is
			// 'localhost' which is not guaranteed to be present in the server certificate.
			UnverifiedConnectionFactory unverifiedConFactory = new UnverifiedConnectionFactory(this.getMyLogger());
			
			// get the trace logger
	    	DSOA2ServiceEnvironment env =  (DSOA2ServiceEnvironment) environment;
	    	Logable traceLogger = env.getTraceLogger(); 
			
	    	// get the number of assertions in the current request 
			String assCountHeader = request.getHeader(SHIB_ASSERTION_COUNT);
			if ( assCountHeader != null && ! assCountHeader.isEmpty() ) {
			
				int assCount = Integer.parseInt( converHeader( assCountHeader ) );
				for ( int i=1 ; i <= assCount; i++ ) {
	
					// for every assertion found construct to retrieval URL header name
					String assUrlHeaderName;
					if ( i < 10 ) {
						assUrlHeaderName = SHIB_ASSERTION + "0" + i;
					} else {
						assUrlHeaderName = SHIB_ASSERTION + i;					
					}
					
					// get the actual retrieval URL
					String assUrlString = request.getHeader( assUrlHeaderName );
					if ( assUrlString != null && ! assUrlString.isEmpty() ) {
	
						try {
						
							// execute a GET request to the retrieved URL
							URL  assURL = new URL(assUrlString);
							HttpsURLConnection assConnection = (HttpsURLConnection) assURL.openConnection();
							assConnection = unverifiedConFactory.getUnverifiedConnection(assConnection);
							
							InputStream assStream = assConnection.getInputStream();
							
						    BufferedReader rd = new BufferedReader(new InputStreamReader(assStream));
						    StringBuilder result = new StringBuilder();
						    String line;
						    
						    // aggregate results into a single buffer
						    while ((line = rd.readLine()) != null) {
						       result.append(line);
						    }
						    
						    rd.close();
							
						    // print SAML Assertion to trace log
						    traceLogger.debug("SAML Assertions Received from " + assUrlString);
						    traceLogger.info(result.toString());
						    
						} catch (MalformedURLException e) {
							this.warn("Malformed URL while requesting Shibboleth Assertion" );
							this.warn(e.getMessage());
						} catch (IOException e) {
							this.warn("Request Error requesting Shibboleth Assertion" );
							this.warn(e.getMessage());
							e.printStackTrace();
						}
						
					} else {
						this.warn("Shibboleth Assertion URL " + assUrlHeaderName + " is empty! Ingoring..." );
					}
					
				}
				
			}
			
		} catch (Exception e) {
			this.warn("Request Error requesting Shibboleth Assertion" );
			this.warn(e.getMessage());
			e.printStackTrace();			
		}
		
		
	}
	
	
	@Override
	protected void printAllParameters(HttpServletRequest request) {
		super.printAllParameters(request);
		
		Enumeration attributes =  request.getAttributeNames();
		System.out.println("Attributes: ");
		
		if ( attributes == null || ! attributes.hasMoreElements() ) {
			System.out.println("  (none)");			
		}
		
		while ( attributes.hasMoreElements() ) {
			Object attName = attributes.nextElement();
			Object attr = request.getAttribute(attName.toString());
			System.out.println("  " + attName + " : " + attr);
		}
		
		System.out.println("Non-Enumarable Attributes: ");
		
		System.out.println("  eppn : " + request.getAttribute("eppn"));
		System.out.println("  eptid : " + request.getAttribute("eptid"));
		System.out.println("  epuid : " + request.getAttribute("epuid"));
		System.out.println("  orgDisplayName : " + request.getAttribute("orgDisplayName"));
		
		System.out.println("  AJP_eppn : " + request.getAttribute("AJP_eppn"));
		System.out.println("  AJP_eptid : " + request.getAttribute("AJP_eptid"));
		System.out.println("  AJP_epuid : " + request.getAttribute("AJP_epuid"));
		System.out.println("  AJP_orgDisplayName : " + request.getAttribute("AJP_orgDisplayName"));		
		
		System.out.println("  Meta_eppn : " + request.getAttribute("Meta_eppn"));
		System.out.println("  Meta_eptid : " + request.getAttribute("Meta_eptid"));
		System.out.println("  Meta_epuid : " + request.getAttribute("Meta_epuid"));		
		System.out.println("  Meta_orgDisplayName : " + request.getAttribute("Meta_orgDisplayName"));
		
		
		System.out.println("  bogusmogus : " + request.getAttribute("bogusmogus"));
		
		try {
			System.out.println("================= REQ CONTENT ================");
			
			BufferedReader reader = request.getReader();
			String sCurrentLine;
			
			while ((sCurrentLine = reader.readLine()) != null) {
				System.out.println(sCurrentLine);
			}

			System.out.println("================= REQ CONTENT ================");
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
				
	}
}
