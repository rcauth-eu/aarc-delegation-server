package org.delegserver.oauth2.servlet;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.DSOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServlet;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import net.minidev.json.JSONObject;

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
		
		JSONObject claims = new JSONObject();
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
		System.out.println(" -------------------- I CLAIM ------------------- ");
		System.out.println(claims.toJSONString());
		System.out.println(" ------------------- I CLAIMED ------------------- ");	
		
		getTransactionStore().save(st);
		
	}
	
}
