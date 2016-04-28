package org.delegserver.oauth2;

import java.util.Map;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.BasicScopeHandler;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;

public class DSDynamicScopeHandler extends BasicScopeHandler {


    /**
     * Returns the {@link UserInfo} object passed to it completed with the claims saved by the 
     * corresponding transaction.
     *
     * @param userInfo being returned to the client 
     * @param transaction the current transaction record
     * @return The UserInfo completed with claims 
     * @throws UnsupportedScopeException exception
     */
	@Override
	public UserInfo process(UserInfo userInfo, ServiceTransaction transaction) throws UnsupportedScopeException {

		//add the claims build based on the requested scopes into the userinfo reply
		
		//get claims previously extracted from the transaction
		DSOA2ServiceTransaction t = (DSOA2ServiceTransaction) transaction;
		Map<String,Object> claims =  t.getClaims();
		
		if ( claims != null ) {
			//some claims might already by set by now, so instead of overwriting them, 
			//simple append the claims from the transaction.
			Map<String,Object> userinfoMap = userInfo.getMap();
			for ( String claim : claims.keySet()) {
				userinfoMap.put(claim, claims.get(claim));
			}
			userInfo.setMap(userinfoMap);
		} else {
			//TODO: fail or just simply pass through? No claims is not necessarily an error 
			//throw new GeneralException("There were no claims saved for this transaction!");
		}
		
		return userInfo;
	}
	
}
