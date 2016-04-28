package org.delegserver.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;

public class DSOA2TransactionKeys extends OA2TransactionKeys {

    protected String claims = "claims";
    protected String user_attributes = "user_attributes";
    protected String trace_record = "trace_record";

    public String claims(String... x) {
        if (0 < x.length) claims = x[0];
        return claims;
    }

    public String user_attributes(String... x) {
        if (0 < x.length) user_attributes = x[0];
        return user_attributes;
    }    

    public String trace_record(String... x) {
        if (0 < x.length) trace_record = x[0];
        return trace_record;
    }        
}
