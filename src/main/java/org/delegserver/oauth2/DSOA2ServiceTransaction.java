package org.delegserver.oauth2;

import java.util.Map;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.core.Identifier;

public class DSOA2ServiceTransaction extends OA2ServiceTransaction {

	public DSOA2ServiceTransaction(AuthorizationGrant ag) {
		super(ag);
	}
	
    public DSOA2ServiceTransaction(Identifier identifier) {
        super(identifier);
    }	

    /* Support for saving claims into the service transaction */
    
    protected Map<String,Object> claims;
    
    public Map<String,Object> getClaims() {
		return claims;
	}
    
    public void setClaims(Map<String,Object> claims) {
		this.claims = claims;
	}
    
    /* Support for saving user attributes released by the idp 
     * into the transaction store 
     */

    protected Map<String,String> userAttributes;
    
    public Map<String, String> getUserAttributes() {
		return userAttributes;
	}
    
    public void setUserAttributes(Map<String, String> userAttributes) {
		this.userAttributes = userAttributes;
	}
    
    /* Support for saving the CN hash used by this transaction
     * This way we can link transactions with trace records.
     */
    
    protected String traceRecord;
    
    public String getTraceRecord() {
		return traceRecord;
	}
    
    public void setTraceRecord(String traceRecord) {
		this.traceRecord = traceRecord;
	}
}
