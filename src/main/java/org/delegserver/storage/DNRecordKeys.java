package org.delegserver.storage;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

public class DNRecordKeys extends SerializationKeys {

	public DNRecordKeys() {
		// the field declared as 'identifier' will be treated as a Primary Key
		identifier(dn_hash);
	}
	
	String dn_hash = "dn_hash";
	String attribute_hash = "attribute_hash";
	String attribute_list = "attribute_list";
	
    public String dn_hash(String... x) {
        if (0 < x.length) dn_hash = x[0];
        return dn_hash;
    }
    
    public String attribute_hash(String... x) {
        if (0 < x.length) attribute_hash = x[0];
        return attribute_hash;
    }	
    
    public String attribute_list(String... x) {
        if (0 < x.length) attribute_list = x[0];
        return attribute_list;
    }	

    
}
