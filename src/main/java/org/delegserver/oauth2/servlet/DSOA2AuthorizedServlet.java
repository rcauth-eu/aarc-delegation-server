package org.delegserver.oauth2.servlet;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.DSOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServlet;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

public class DSOA2AuthorizedServlet extends OA2AuthorizedServlet {

	@Override
	protected OA2ServiceTransaction createNewTransaction(AuthorizationGrant grant) {
		return new DSOA2ServiceTransaction(grant);
	}

	public static String MULTI_VAL_DELIMITED = ";";
	
	/**
	 * It searches the request object for the requested key. It uses the following order of preference:
	 * - PARAMETERS 
	 * - ATTRIBUTES
	 * - HEADERS
	 * 
	 * @param request
	 * @param key
	 * @return the value of the requested key parameter 
	 */
    protected Object getParam(HttpServletRequest request, String key) {
             
        // account for multi-valued PARAMETER
        String[] param = request.getParameterValues(key);
        if ( param != null && param.length != 0 ) {
        	return parseMultiValue( Arrays.asList(param) );
        }
        
        // check key between request ATTRIBUTES
        // multi-values ATTRIBUTES, not sure.....
        Object o = request.getAttribute(key);
        if (o != null) {
        	return o.toString();
        }
    
        
        // account for multi-values HEADER
        Enumeration<String> header = request.getHeaders(key);
        if ( header != null && header.hasMoreElements() ) {
        	return parseMultiValue( Collections.list(header) );	
        }
        
        return null;
    }
    
    
    
    protected Object parseMultiValue(List<String> value) {
    
		if ( value.size() == 1 && ! value.get(0).contains(MULTI_VAL_DELIMITED) ) {
        	//single value
    		return value.get(0);
    	} else {
    		//multi value
    		List<String> multiValue = new ArrayList<String>();
        	for (String v : value) {
        		multiValue.addAll(  Arrays.asList( v.split(MULTI_VAL_DELIMITED)) );
        	}
        	return multiValue;
    	}
    }
	
	@Override
	public void preprocess(TransactionState state) throws Throwable {
		super.preprocess(state);
		
		printAllParameters(state.getRequest());
		
		DSOA2ServiceTransaction st = (DSOA2ServiceTransaction) state.getTransaction();
		
		Map<String,Object> claims = new HashMap<String,Object>();
		for (String scope : st.getScopes()) {
			
			Map <String,String> claimMap = ((DSOA2ServiceEnvironment)getServiceEnvironment()).getClaimsMap(scope);
			if ( claimMap != null ) {
				for ( String claim : claimMap.keySet() ) {
					
					String attribute = claimMap.get(claim);
					Object value = getParam(state.getRequest(), attribute);
					
					if (value != null) {
						claims.put(claim, value);
					}
					
				}
			}
			
		}
		
		st.setClaims(claims);
		getTransactionStore().save(st);
		
	}
	
}
