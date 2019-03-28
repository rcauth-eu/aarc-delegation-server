package eu.rcauth.delegserver.storage;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

public class TraceRecordKeys extends SerializationKeys {

	public TraceRecordKeys() {
		// the field declared as 'identifier' will be treated as a Primary Key
		identifier(cn_hash);
	}
	
	String cn_hash = "cn_hash";
	String sequence_nr = "sequence_nr";
	String attribute_hash = "attribute_hash";
	String attribute_salt = "attribute_salt";
	String attribute_names = "attribute_names";
	
    public String cn_hash(String... x) {
        if (0 < x.length) cn_hash = x[0];
        return cn_hash;
    }
    
    public String attribute_hash(String... x) {
        if (0 < x.length) attribute_hash = x[0];
        return attribute_hash;
    }	
    
    public String attribute_salt(String... x) {
        if (0 < x.length) attribute_salt = x[0];
        return attribute_salt;
    }	
    
    public String attribute_names(String... x) {
        if (0 < x.length) attribute_names = x[0];
        return attribute_names;
    }   
    
    public String sequence_nr(String... x) {
        if (0 < x.length) sequence_nr = x[0];
        return sequence_nr;
    }   
    
}
