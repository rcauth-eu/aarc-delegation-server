package org.delegserver.oauth2.servlet;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.DSOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
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
        	
        	/* DEBUG */
        	env.getTraceLogger().marked("NEW AUTHORIZE REQUEST [transaction: " + serviceTransaction.getIdentifierString()  +"]");
        	printAllParameters( authorizedState.getRequest() );
        	
        	
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
    		//       Update: AbstractAuthorizationServlet hardcodes the use of headers and fails 
    		//               if UseHeader are not enabled. Ask Jim?
        	serviceTransaction.setUserAttributes( getHeaderMap(state.getRequest()) );

        	// save transaction
    		getTransactionStore().save(serviceTransaction);
        	
        }
	}
	
	/* EXTACTING PARAMETERS FORM REQUEST */

	/**
	 * Construct a map based on the variables contained in the request header.
	 * 
	 * @param request Incoming request
	 * @return Map created from the headers in the request 
	 */
	protected Map<String,String> getHeaderMap(HttpServletRequest request) {
		
		Map<String,String> map = new HashMap<String,String>();
		
		// iterate over headers 
        Enumeration e = request.getHeaderNames();
        while (e.hasMoreElements()) {
        	
            String name = e.nextElement().toString();
            // convert into the right encoding
            String value = converHeader( request.getHeader(name));
            
            if ( value != null && ! value.isEmpty() ) { 
            	map.put(name , value );
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
	 *  Shibboleth separates multi valued variables with a special delimiter. We have to account for this 
	 *  in order to support multi valued claims! See https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAttributeAccess
	 */
	public static String SHIB_MULTI_VAL_DELIMITED = ";";
	
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
        	return parseMultiValue( Arrays.asList(param) );
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
            headerValues.add( converHeader(value) );
        }
        if ( ! headerValues.isEmpty() ) {
        	return parseMultiValue(headerValues);
        }
        
        /* GIVE UP */
        
        return null;
    }
    
    
    /**
     * Parse a potentially multi valued attribute. It either returns a single value found,  or a {@link List}
     * of {@link String} in case of multi-valued attributes.
     *  
	 * Note! Split single values containing the MULTI_VAL_DELIMITED. Since shibboleth handles multi-valued 
	 * attributes by bundling them into a single attributes and separated with ";" we account for these here.   
     *  
     * @param value List of values to parse for potential multi values attributes
     * @return A single {@link String} or a {@link List} of {@link String} in case of multi-valued attributes
     */
    protected Object parseMultiValue(List<String> value) {
/*    
		if ( value.size() == 1 && ! value.get(0).contains(SHIB_MULTI_VAL_DELIMITED) ) {
        	
			//single value
    		String ret = value.get(0);
    		if ( ret != null && ! ret.isEmpty() ) {
    			return ret;
    		} else {
    			return null;
    		}
    		
    	} else {
*/    		
    		//multi value
    		List<String> multiValue = new ArrayList<String>();
    		
        	for (String combinedValue : value) {
        		
        		if ( combinedValue != null && ! combinedValue.isEmpty() )
        		
        		for (String v : combinedValue.split(SHIB_MULTI_VAL_DELIMITED)) {
        			if ( ! multiValue.contains(v) ) {
        				multiValue.add(v);
        			}
        		}
        		
        	}
        	
        	if ( multiValue.isEmpty() ) {
        		return null;
        	} else if ( multiValue.size() == 1 ) {
        		return multiValue.get(0);
        	} else {
        		return multiValue;
        	}
        	
//    	}
    }	
	
    /* DEBUG AND DISPLAY */
	
	@Override
	protected void printAllParameters(HttpServletRequest request) {
		
    	DSOA2ServiceEnvironment env =  (DSOA2ServiceEnvironment) environment;
    	Logger traceLogger = env.getTraceLogger().getLogger(); 
		
		String reqUrl = request.getRequestURL().toString();
        String queryString = request.getQueryString();   // d=789
        if (queryString != null) {
            reqUrl += "?" + queryString;
        }
        
        traceLogger.info("Request parameters for '" + reqUrl + "'");

        if (request.getParameterMap() == null || request.getParameterMap().isEmpty()) {
        	traceLogger.info("  (none)");
        } else {
            for (Object key : request.getParameterMap().keySet()) {
                String[] values = request.getParameterValues(key.toString());
                traceLogger.info(" " + key + ":");
                if (values == null || values.length == 0) {
                	traceLogger.info("   (no values)");
                } else {
                    for (String x : values) {
                    	traceLogger.info("   " + x);
                    }
                }
            }
        }
        traceLogger.info("Cookies:");
        if (request.getCookies() == null) {
        	traceLogger.info(" (none)");
        } else {
            for (javax.servlet.http.Cookie c : request.getCookies()) {
            	traceLogger.info(" " + c.getName() + "=" + c.getValue());
            }
        }
        traceLogger.info("Headers:");
        Enumeration e = request.getHeaderNames();
        if (!e.hasMoreElements()) {
        	traceLogger.info(" (none)");
        } else {
            while (e.hasMoreElements()) {
                String name = e.nextElement().toString();
                traceLogger.info(" " + name);
                traceLogger.info("   " + request.getHeader(name));
            }
        }
		

        traceLogger.info("Attributes:");
        Enumeration attr = request.getAttributeNames();
        if (!e.hasMoreElements()) {
        	traceLogger.info(" (none)");
        } else {
            while (attr.hasMoreElements()) {
                String name = attr.nextElement().toString();
                traceLogger.info(" " + name);
                traceLogger.info("   " + request.getAttribute(name));
            }
        }
        
	}
	

}
