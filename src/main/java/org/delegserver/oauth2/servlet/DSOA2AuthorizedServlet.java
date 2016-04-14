package org.delegserver.oauth2.servlet;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
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
    protected String getParam(HttpServletRequest request, String key) {
        String x = null;
        
        // Check key between request PARAMETERS
        x = request.getParameter(key);
        if (x != null) return x;
        
        // Check key between request ATTRIBUTES
        Object o = request.getAttribute(key);
        if (o != null) return o.toString();
    
        // Check key between request HEADERS
        x = request.getHeader(key);
        return x;
    }
	
	@Override
	public void preprocess(TransactionState state) throws Throwable {
		super.preprocess(state);
		
		DSOA2ServiceTransaction st = (DSOA2ServiceTransaction) state.getTransaction();
		
		Map<String,String> claims = new HashMap<String,String>();
		for (String scope : st.getScopes()) {
			
			Map <String,String> claimMap = ((DSOA2ServiceEnvironment)getServiceEnvironment()).getClaimsMap(scope);
			if ( claimMap != null ) {
				for ( String claim : claimMap.keySet() ) {
					
					String attribute = claimMap.get(claim);
					String value = getParam(state.getRequest(), attribute);
					
					if (value != null) {
						claims.put(claim, value);
					}
					
				}
			}
			
		}
		
		st.setClaims(claims);
		getTransactionStore().save(st);
		
		JSONObject jsonClaims = new JSONObject(claims);
		System.out.println(" -------------------- I CLAIM ------------------- ");
		System.out.println(jsonClaims.toJSONString());
		System.out.println(" ------------------- I CLAIMED ------------------- ");	
		
		String claimString = jsonClaims.toString();
		byte[] blob = Base64.encodeBase64(claimString.getBytes());
		
		System.out.println(" -------------------- I CLAIM BLOB ------------------- ");
		System.out.println(new String(blob));
		System.out.println(" ------------------- I CLAIMED BLOB ------------------- ");			

		System.out.println(" -------------------- CLAIM BLOB - TEST ------------------- ");
		
		JSONParser parserBlob = new JSONParser(0);
		Object objBlob = parserBlob.parse( Base64.decodeBase64(blob) );
		if ( objBlob instanceof JSONObject ) {
			System.out.println(" JSONOBJECT ");
			System.out.println(((JSONObject)objBlob).toJSONString());
		} else {
			System.out.println(" I am a " + objBlob.getClass().getCanonicalName());
		}
		
		System.out.println(" -------------------- CLAIM BLOB - TEST ------------------- ");		
		
		System.out.println(" -------------------- CLAIM - TEST ------------------- ");
		
		JSONParser parser = new JSONParser(0);
		Object obj = parser.parse(claimString);
		if ( obj instanceof JSONObject ) {
			System.out.println(" JSONOBJECT ");
			System.out.println(((JSONObject)obj).toJSONString());
		} else {
			System.out.println(" I am a " + obj.getClass().getCanonicalName());
		}
		
		System.out.println(" -------------------- CLAIM - TEST ------------------- ");
		
	}
	
}
