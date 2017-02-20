package org.delegserver.oauth2;

import java.util.Map;
import java.util.Collection;
import java.util.HashSet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.BasicScopeHandler;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;

import org.delegserver.oauth2.DSOA2ServiceEnvironment;

/**
 * Custom ScopeHandler that adds claims into UserInfo and IDToken 
 * 
 * @author "Tamás Balogh"
 */
public class DSDynamicScopeHandler extends BasicScopeHandler {

    /**
     * Returns the {@link UserInfo} object passed to it completed with the claims saved by the 
     * corresponding transaction.
     *
     * @param userInfo being returned to the client 
     * @param transaction the current transaction record
     * @return The UserInfo completed with claims 
     */
    @Override
    public UserInfo process(UserInfo userInfo, ServiceTransaction transaction) {

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
	    //don't fail on empty claims 
	}
	
	return userInfo;
    }

    /**
     * Return a flattened list of all the claims in all the scopes as configured
     * in the <scopes> node
     * @return complete set of configured claims
     */
    @Override
    public Collection<String> getClaims() {
	HashSet<String> claims = new HashSet<>();
	DSOA2ServiceEnvironment dsoa2se = (DSOA2ServiceEnvironment)getOa2SE();
	Map<String,Map<String,String>> scopesMap = dsoa2se.getScopesMap();

	// iterate of scope -> claimsMap
	for (Map.Entry<String,Map<String,String>> entry : scopesMap.entrySet()) {
	    Map<String,String> claimsMap = entry.getValue();
	    // some scopes can be without claims
	    if (claimsMap == null)  {
		dsoa2se.info("Skipping scope with no claims: "+entry.getKey());
	    } else {
//		dsoa2se.debug("Adding claims from scope: "+entry.getKey());
		claims.addAll(claimsMap.keySet());
	    }
	}
	return claims;
    }
}
