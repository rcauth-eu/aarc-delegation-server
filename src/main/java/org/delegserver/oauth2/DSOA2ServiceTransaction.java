package org.delegserver.oauth2;

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

    
}
