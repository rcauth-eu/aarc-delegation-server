package org.delegserver.oauth2;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.util.Map;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

public class DNGenerator {

	public static String O_DELIMITER = " ";
	public static String CN_DELIMITER = " ";
	public static String RDN_TRUNCATE_SIGN = "...";
	public static int RDN_MAX_SIZE = 64;
	
	protected Object[] cnNameSources = null; 
	protected Object[] cnUniqueIDSources = null;
	protected Object[] orgSources = null;
	
	public DNGenerator(Object[] cnNameSources, Object[] cnUniqueIDSources, Object[] orgSources) {
		this.cnNameSources = cnNameSources;
		this.cnUniqueIDSources = cnUniqueIDSources;
		this.orgSources = orgSources;
	}
	
	public Object[] getCnNameSources() {
		return cnNameSources;
	}
	
	public Object[] getCnUniqueIDSources() {
		return cnUniqueIDSources;
	}
	
	public Object[] getOrgSources() {
		return orgSources;
	}
	
	public String getOrganisation(Map<String,String> attributeMap) throws UnsupportedEncodingException {
		
		String[] orgSourceAttrs = null;
		
		for ( Object obj : orgSources ) {
			
			if (obj instanceof String) {
				// single attribute 
				if ( attributeMap.containsKey((String)obj)) {
					// single attribute is present in attribute map
					orgSourceAttrs = new String[] { (String)obj };
					// attribute present! use it!
					break;
				}
    		} else {
    			// concatenation of attributes 
    			String[] sources = (String[])obj;
    			boolean sourcesPresent = true;
    			for (String s : sources) {
    				if ( ! attributeMap.containsKey(s) ) {
    					sourcesPresent = false;
    				}
    			}
    			if ( sourcesPresent ) {
    				// attributes present! use them!
    				orgSourceAttrs = sources;
    				break;
    			}
    		}
		}
		
		if ( orgSourceAttrs == null ) {
			throw new GeneralException("No suitable attribute found for building 'Organization' attribute!");
		}
		
		//TODO: custom rule for entityID
		
		String organisation = null;
		for (String source : orgSourceAttrs) {
			if ( organisation == null ) {
				organisation = attributeMap.get(source);
			} else {
				organisation += O_DELIMITER + attributeMap.get(source);
			}
		}
		
		if ( organisation.getBytes("UTF-8").length > RDN_MAX_SIZE ) {
			organisation = truncate(organisation);
		}
		
		return organisation;
	}
	
	
	private String truncate(String rdn) throws UnsupportedEncodingException {
		
		int truncatedSize = RDN_MAX_SIZE - RDN_TRUNCATE_SIGN.getBytes("UTF-8").length;
		
		Charset utf8Charset = Charset.forName("UTF-8");
		CharsetDecoder cd = utf8Charset.newDecoder();
		
		byte[] sba = rdn.getBytes("UTF-8");
		
		// Ensure truncating by having byte buffer = DB_FIELD_LENGTH
		ByteBuffer bb = ByteBuffer.wrap(sba, 0, truncatedSize); // len in [B]
		CharBuffer cb = CharBuffer.allocate(truncatedSize); // len in [char] <= # [B]
		
		// Ignore an incomplete character
		cd.onMalformedInput(CodingErrorAction.IGNORE);
		cd.decode(bb, cb, true);
		cd.flush(cb);
		
		rdn = new String(cb.array(), 0, cb.position()) + RDN_TRUNCATE_SIGN;
		
		return rdn;
	}

	private void printDNSources() {
    	
    	System.out.println("CN NAME SOURCES :");
    	System.out.println("---------------------------------------------------------------------");
    	for (Object obj : cnNameSources) {
    		if (obj instanceof String) {
            	System.out.println("		" + ((String)obj));
    		} else {
    			String[] sources = (String[])obj;
    			System.out.print("		");
    			for (String s : sources) {
    				System.out.print(s + " ");
    			}
    			System.out.println("");
    		}
    	}
    	System.out.println("---------------------------------------------------------------------");
    	
    	System.out.println("CN UNIQUE ID SOURCES :");
    	System.out.println("---------------------------------------------------------------------");
    	for (Object obj : cnUniqueIDSources) {
    		if (obj instanceof String) {
            	System.out.println("		" + ((String)obj));
    		} else {
    			String[] sources = (String[])obj;
    			System.out.print("		");
    			for (String s : sources) {
    				System.out.print(s + " ");
    			}
    			System.out.println("");
    		}
    	}
    	System.out.println("---------------------------------------------------------------------");        	
    	
    	System.out.println("ORG SOURCES :");
    	System.out.println("---------------------------------------------------------------------");
    	for (Object obj : orgSources) {
    		if (obj instanceof String) {
            	System.out.println("		" + ((String)obj));
    		} else {
    			String[] sources = (String[])obj;
    			System.out.print("		");
    			for (String s : sources) {
    				System.out.print(s + " ");
    			}
    			System.out.println("");
    		}
    	}
    	System.out.println("---------------------------------------------------------------------"); 
    			
	}
		
}
