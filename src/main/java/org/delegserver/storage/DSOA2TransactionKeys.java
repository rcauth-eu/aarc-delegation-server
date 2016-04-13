package org.delegserver.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;

public class DSOA2TransactionKeys extends OA2TransactionKeys {

    protected String claims = "claims";

    public String claims(String... x) {
        if (0 < x.length) claims = x[0];
        return claims;
    }
	
}
