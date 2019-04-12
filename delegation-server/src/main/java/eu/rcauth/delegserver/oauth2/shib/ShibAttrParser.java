package eu.rcauth.delegserver.oauth2.shib;

import java.util.ArrayList;
import java.util.List;

public class ShibAttrParser {

	/**
	 *  Shibboleth separates multi valued variables with a special delimiter. We have to account for this 
	 *  in order to support multi valued claims! See https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAttributeAccess
	 */
	public static final String SHIB_MULTI_VAL_DELIMITED = ";";
	
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
			List<String> tmpValues = new ArrayList<>();
			
			// put every single attribute in the result set
			// Note: don't replace with for(...:...) since that's less efficient for an array
			for (int i=0 ; i<subAttrs.length; i++) {
				// unescape any previously escaped attribute
				String v = subAttrs[i].replaceAll("\\\\;", ";");
				
				// filter any duplicate and empty entries
				if ( ! v.isEmpty() && ! tmpValues.contains(v) ) {
					tmpValues.add(v);
				}
			}
			
			values = tmpValues.toArray(new String[0]);
			
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
	
	public static String combineMultiValuedAttr(List<String> attr) {
		
		StringBuilder value = new StringBuilder();
		
		for( String v : attr ) {
			// escape any delimiter that is in the attribute originally
			// so that it wouldn't become a delimiter itself 
			v = v.replaceAll(SHIB_MULTI_VAL_DELIMITED, "\\\\" + SHIB_MULTI_VAL_DELIMITED);
			value.append((value.length() == 0) ? v : SHIB_MULTI_VAL_DELIMITED + v);
		}
		
		return value.toString();
		
	}
	
}
