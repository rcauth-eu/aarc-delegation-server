package eu.rcauth.delegserver.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;

public class DSOA2TransactionKeys extends OA2TransactionKeys {

    protected String claims = "claims";
    protected String user_attributes = "user_attributes";
    protected String cn_hash = "trace_record";
    protected String sequence_nr = "sequence_nr";

    public String claims(String... x) {
        if (0 < x.length)
            claims = x[0];
        return claims;
    }

    public String user_attributes(String... x) {
        if (0 < x.length)
            user_attributes = x[0];
        return user_attributes;
    }

    public String cn_hash(String... x) {
        if (0 < x.length)
            cn_hash = x[0];
        return cn_hash;
    }

    public String sequence_nr(String... x) {
        if (0 < x.length)
            sequence_nr = x[0];
        return sequence_nr;
    }
}
