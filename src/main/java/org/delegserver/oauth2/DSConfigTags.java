package org.delegserver.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;

/**
 * @author "Tamás Balogh"
 *
 */
public interface DSConfigTags extends OA4MPConfigTags {

	/* TRACEABILITY */
	
	// DN generator tags used to specify DN sources 
	public static final String DN_GENERATOR = "dnGenerator";
	public static final String DN_GENERATOR_CN_NAME = "cnName";
	public static final String DN_GENERATOR_CN_UNIQUE_ID = "cnUniqueId";
	public static final String DN_GENERATOR_ORGANISATION = "organisation";
	public static final String DN_GENERATOR_EXTENSIONS = "extensions";

	public static final String DN_GENERATOR_SOURCE = "source";
	public static final String DN_GENERATOR_SOURCE_NAME = "name";
	public static final String DN_GENERATOR_SOURCE_FILTER = "filter";
	
	// attribute filter tags
	public static final String ATTR_FILTERS = "attributeFilters";
	public static final String ATTR_FILTER = "filter";
	public static final String ATTR_FILTER_NAME = "name";
	
	// the name of the trace_records store backend
	public static final String TRACE_RECORD_STORE = "traceRecords";

	/* SCOPES AND CLAIMS */
	
	// this is an attribute of the <scope> tag 
	public static final String SCOPE_NAME = "name";
	public static final String CLAIM_NAME = "name";
	
	// a claim belonging to a scope 
	public static final String SCOPE_CLAIM = "claim";
	
}
