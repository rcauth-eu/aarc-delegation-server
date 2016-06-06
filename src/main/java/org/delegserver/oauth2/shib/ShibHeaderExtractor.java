package org.delegserver.oauth2.shib;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

public class ShibHeaderExtractor {

	/**
	 * Get a specific request attribute identified by the given key
	 * <p>
	 * It either returns a single {@link String} value found, or a 
	 * {@link List} of {@link String}s in case of multi-valued attributes. 
	 *   
	 * @param request The request containing the attribute
	 * @param key The key identifying the attribute
	 * @return The attribute matching the key from the given request
	 * 
	 */
	public static Object getRequestAttrs(HttpServletRequest request, String key) {

        Enumeration<?> header = request.getHeaders(key);
        
        if ( header != null ) {
        	
        	List<String> headerValues = new ArrayList<String>();
        	
	        while ( header.hasMoreElements() ) {
	        	String value = header.nextElement().toString();
	        	
	            // convert into the right encoding 
	        	value = converHeader(value);
	        	
	        	if ( value != null && ! value.isEmpty() ) {
		            String[] values = ShibAttrParser.parseMultiValuedAttr( value );
		            
		            if (  values != null ) {
		            	headerValues.addAll( Arrays.asList(values) );
		            }
	        	}
	        }
	        
	        if ( ! headerValues.isEmpty() ) {
	        	if ( headerValues.size() == 1 ) {
	        		return headerValues.get(0);
	        	} else {
	        		return headerValues;
	        	}
	        }
	        
        }
        
        return null;
		
	}
	
	/**
	 * Does the same as {@link #getRequestAttrs(HttpServletRequest, String)}, but 
	 * it does not account for multi-valued headers. It simply returns the first
	 * header found with any value.
	 * <p>
	 * Be aware that this might return a multi-valued string with a shibboleth
	 * delimiter (;) !
	 * 
	 * @param request The request containing the attribute
	 * @param The key identifying the attribute
	 * @return The first attribute matching the key from the given request
	 */
	public static String getRequestAttr(HttpServletRequest request, String key) {
		
		String value = request.getHeader(key);
		
		if ( value != null && ! value.isEmpty() ) {
			return converHeader(value);
		}
		
		return null;
	}
	

	/**
	 * Get the whole attribute map belonging to the request
	 * 
	 * @param request The request containing the attributes
	 * @return A map containing the request attributes
	 */
	public static Map<String, Object> getAttrMap(HttpServletRequest request) {

		Map<String,Object> map = new HashMap<String,Object>();
		
		// iterate over headers 
        Enumeration e = request.getHeaderNames();
        while (e.hasMoreElements()) {
        	
        	String name = e.nextElement().toString();
        	
        	// convert into the right encoding
            Object header = getRequestAttrs(request, name);
            
            if ( header != null ) {
            
            	if ( header instanceof String ) {
            		
            		map.put(name , ((String)header) );
            		
            	} else {
            	
		            List<String> values = (List<String>) header;
		            
		            if ( values.size() == 1 ) {
		            	map.put(name , values.get(0));
		            } else {
		            	map.put(name , values);
		            }
		            
            	}
	            
            }
        }
		
		return map;		
		
	}

	
	/**
	 * Account for the encoding of the request headers (ISO-8859-1) and convert it to UTF-8
	 * @param value Header value in ISO-8859-1 encoding 
	 * @return Header value in UTF-8 encoding
	 */
	protected static String converHeader(String value) {
		// IMPORTANT !!! Map the header parameters with the right encoding 
		Charset isoCharset = Charset.forName("ISO-8859-1");
		Charset utf8Charset = Charset.forName("UTF-8");		
		
        byte[] v = value.getBytes(isoCharset);
        return new String(v,utf8Charset);
	}
}
