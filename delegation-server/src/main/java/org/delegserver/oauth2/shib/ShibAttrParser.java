package org.delegserver.oauth2.shib;

import java.util.ArrayList;
import java.util.List;

public class ShibAttrParser {

	/**
	 *  Shibboleth separates multi valued variables with a special delimiter. We have to account for this 
	 *  in order to support multi valued claims! See https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAttributeAccess
	 */
	public static String SHIB_MULTI_VAL_DELIMITED = ";";	
	
    /**
     * Parse a potentially multi valued attribute. In case of single valued attributes it will simply return
     * an array with a single element
     * <p> 
	 * Note! Split single values containing the MULTI_VAL_DELIMITED. Since shibboleth handles multi-valued 
	 * attributes by bundling them into a single attributes and separated with ";" we account for these here.   
     *  
     * @param attr The attribute to split according to the shibboleth delimiter
     * @return A String array containing the list of parsed attributes. 
     */
	public static String[] parseMultiValuedAttr(String attr) {

		// the returned value set
		String[] values = null;
		
		// match unescaped delimiters
		if ( attr.matches(".+[^\\\\]" + SHIB_MULTI_VAL_DELIMITED  + ".+") ) {

			//remove any leading delimiter
			attr = attr.replaceAll("^;+", "");
		
			// split with negative lookbehind
			String[] subAttrs = attr.split("(?<!\\\\)" + SHIB_MULTI_VAL_DELIMITED);
			List<String> tmpValues = new ArrayList<String>();
			
			// put every single attribute in the result set
			for (int i=0 ; i<subAttrs.length; i++) {
				// unescape any previously escaped attribute
				String v = subAttrs[i].replaceAll("\\\\;", ";");
				
				// filter any duplicate and empty entries
				if ( ! v.isEmpty() && ! tmpValues.contains(v) ) {
					tmpValues.add(v);
				}
			}
			
			values = tmpValues.toArray(new String[tmpValues.size()]);
			
		} else {
			
			if ( ! attr.isEmpty() ) {
				values = new String[1];
				// unescape previously escaped attribute
				values[0] = attr.replaceAll("\\\\;", ";");
			} else {
				return null;
			}
		}
		
		return values;
	}
	
	public static String combineMultiValuedAttr(String[] attr) {
		
		String value = "";
		
		for( String v : attr ) {
			v = v.replaceAll(";", "\\\\;");
			value += (value.isEmpty()) ? v : SHIB_MULTI_VAL_DELIMITED + v;
		}
		
		return value;
		
	}
	
}
