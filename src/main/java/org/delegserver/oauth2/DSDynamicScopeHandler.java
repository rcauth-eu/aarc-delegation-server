package org.delegserver.oauth2;

import java.util.Map;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.BasicScopeHandler;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;

public class DSDynamicScopeHandler extends BasicScopeHandler {

	@Override
	public UserInfo process(UserInfo userInfo, ServiceTransaction transaction) throws UnsupportedScopeException {

		DSOA2ServiceTransaction t = (DSOA2ServiceTransaction) transaction;
		Map<String,String> claims =  t.getClaims();
		for ( String claim : claims.keySet()) {
			userInfo.put(claim, claims.get(claim));
		}
		
		return userInfo;
	}
	
}
