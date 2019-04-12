package eu.rcauth.delegserver.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;

/**
 * @author "Tamás Balogh"
 *
 */
public interface DSConfigTags extends OA4MPConfigTags {

	/* TRACEABILITY */
	
	// DN generator tags used to specify DN sources 
	String DN_GENERATOR = "dnGenerator";
	String DN_GENERATOR_ATTRIBUTE = "attributeName";
	String DN_GENERATOR_TYPE = "type";
	String DN_GENERATOR_BASE_DN = "baseDN";
	
	String DN_GENERATOR_CN_NAME = "cnName";
	String DN_GENERATOR_CN_UNIQUE_ID = "cnUniqueId";
	String DN_GENERATOR_ORGANISATION = "organisation";
	String DN_GENERATOR_EXTENSIONS = "extensions";

	String DN_GENERATOR_SOURCE = "source";
	String DN_GENERATOR_SOURCE_NAME = "name";
	String DN_GENERATOR_SOURCE_FILTER = "filter";
	
	// attribute filter tags
	String ATTR_FILTERS = "attributeFilters";
	String ATTR_FILTER = "filter";
	String ATTR_FILTER_NAME = "name";
	
	// the name of the trace_records store backend
	String TRACE_RECORD_STORE = "traceRecords";

	/* SCOPES AND CLAIMS */
	
	// this is an attribute of the <scope> tag 
	String SCOPE_NAME = "name";
	String CLAIM_NAME = "name";
	
	// a claim belonging to a scope 
	String SCOPE_CLAIM = "claim";
	
}
