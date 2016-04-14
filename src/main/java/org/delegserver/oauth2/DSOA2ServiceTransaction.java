package org.delegserver.oauth2;

import java.util.Map;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import net.minidev.json.JSONObject;
import edu.uiuc.ncsa.security.core.Identifier;

public class DSOA2ServiceTransaction extends OA2ServiceTransaction {

	public DSOA2ServiceTransaction(AuthorizationGrant ag) {
		super(ag);
	}
	
    public DSOA2ServiceTransaction(Identifier identifier) {
        super(identifier);
    }	

    protected Map<String,String> claims;
    
    public Map<String,String> getClaims() {
		return claims;
	}
    
    public void setClaims(Map<String,String> claims) {
		this.claims = claims;
	}
    
}
