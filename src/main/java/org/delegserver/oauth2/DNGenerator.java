package org.delegserver.oauth2;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
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
	public static int CN_DISPAY_NAME_MAX_SIZE = 43;	
	
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
	
	/* METHODS FOR CONSTRUCTING THE USER DN FROM AN ATTRIBUTE MAP */

	/**
	 * Build the Organization (O) RDN from a set of input attributes, following the RCauth Policy Document
	 * ( https://rcauth.eu/policy ) section 3.1.2. This RDN is expected to be built from one of the 
	 * attribute sources defined under 'organisation' in the 'dnGenerator' configuration. 
	 * 
	 * In case no appropriate source attributes are found the the provided map, an exception
	 * will be thrown. 
	 * 
	 * @param attributeMap Attribute source for building the O RDN
	 * @return The constructed O RDN (without the '/O=' prefix!)
	 * @throws UnsupportedEncodingException
	 */
	public String getOrganisation(Map<String,String> attributeMap) throws UnsupportedEncodingException {
		
		// Pick out the attribute source from the predefined configuration which is present in the 
		// provided attributeMap. Throw and exception if no suitable source is found.
		
		String[] orgSourceAttrs = chooseAttrSource(orgSources,attributeMap);
		
		if ( orgSourceAttrs == null ) {
			throw new GeneralException("No suitable attribute found for building 'Organization' attribute!");
		}
		
		// Build the O RDN from the selected source attribute. Use the getProcessedAttr to 
		// process the attribute value before setting it in the RDN
		
		String organisation = null;
		for (String source : orgSourceAttrs) {
			if ( organisation == null ) {
				organisation = getProcessedAttr(attributeMap, source);
			} else {
				organisation += O_DELIMITER + getProcessedAttr(attributeMap, source);
			}
		}
		
		// Do some post-processing on the created RDN, like length check. 
		organisation = truncate(organisation, RDN_MAX_SIZE);
		
		return organisation;
	}

	public String getCommonName(Map<String,String> attributeMap) throws UnsupportedEncodingException {
		
		// First deal with the display name part of the common name
		
		String[] cnNameSourceAttr = chooseAttrSource(cnNameSources,attributeMap);
		if ( cnNameSourceAttr == null ) {
			throw new GeneralException("No suitable attribute found for building the Display Name part of the 'CommonName' attribute!");
		}		
		
		String diplayName = null;
		for (String source : cnNameSourceAttr) {
			if ( diplayName == null ) {
				diplayName = getProcessedAttr(attributeMap, source);
			} else {
				diplayName += CN_DELIMITER + getProcessedAttr(attributeMap, source);
			}
		}
		
		diplayName = truncate(diplayName,CN_DISPAY_NAME_MAX_SIZE);
		
		return diplayName;
	}
	
	/* HELPER METHODS */
	
	protected String[] chooseAttrSource(Object[] attrSources, Map<String,String> attributeMap) {
		
		String[] selectedAttrSource = null;
		
		for ( Object obj : attrSources ) {
			
			if (obj instanceof String) {
				// single attribute 
				if ( attributeMap.containsKey((String)obj) && ! attributeMap.get((String)obj).isEmpty() ) {
					// single attribute is present in attribute map and it's not empty
					selectedAttrSource = new String[] { (String)obj };
					// attribute present! use it!
					break;
				}
    		} else {
    			// concatenation of attributes 
    			String[] sources = (String[])obj;
    			boolean sourcesPresent = true;
    			for (String s : sources) {
    				if ( ! attributeMap.containsKey(s) || attributeMap.get(s).isEmpty() ) {
    					//one of the keys are not present, or it's empty, therefore ignore it
    					sourcesPresent = false;
    				}
    			}
    			if ( sourcesPresent ) {
    				// attributes present! use them!
    				selectedAttrSource = sources;
    				break;
    			}
    		}
		}		
		return selectedAttrSource;
	}
	
	
	protected String getProcessedAttr(Map<String,String> attributeMap, String attributeKey) {
		
		if ( attributeMap == null || attributeKey == null || ! attributeMap.containsKey(attributeKey) ) {
			return null;
		}
		
		String attribute = attributeMap.get(attributeKey);
		
		/* SPECIAL RULES FOR CERTAIN ATTRIBUTES SHOULD GO HERE */
		
		// TODO: maybe don't hardcode things like "entityID" or "Shib-Identity-Provider" and just
		// simply try to parse a URL in any case for its domain name.
		
		// special case for entityIDs that are URLs 
		if ( attributeKey.equals("entityID") || attributeKey.equals("Shib-Identity-Provider") ) {
			try {
				// try converting to a URL
				URL url = new URL(attribute);
				return url.getHost();
			} catch (MalformedURLException e) {
				// if the conversion fails the take the value as it is (is it a URN?)
				return attribute;
			}
		}
		
		/* END OF SPECIAL RULES */
		
		return attribute;
	}
	
	/**
	 * Implementation of the general truncating rule outlined in the RCauth Policy Document
	 * ( https://rcauth.eu/policy ) in section 3.1.2. It takes an RDN as input and checks its
	 * UTF-8 encoded byte size. In case it's larger than the size provided in the parameters,
	 * the RDN will get truncated to 61 UTF-8 bytes (or less in case the brodering byte is 
	 * in the middle of a UTF-8 character definition) with RDN_TRUNCATE_SIGN appended to the
	 * end.
	 * 
	 * @param rdn Input RDN to be truncated in case it's too large 
	 * @param size The size to which the RDN should be truncated. This value defaults to 
	 * RDN_MAX_SIZE (64 bytes) in case the size provided is <= 0 
	 * @return Truncated RDN 
	 * @throws UnsupportedEncodingException
	 */
	protected String truncate(String rdn,int size) throws UnsupportedEncodingException {
		
		if ( size <= 0 ) {
			size = RDN_MAX_SIZE;
		}
		
		// only truncate if the RDN exceeds the maximum allowed size
		if ( rdn.getBytes("UTF-8").length > size ) {
		
			int truncatedSize = size - RDN_TRUNCATE_SIGN.getBytes("UTF-8").length;
			
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
			
		}
		
		return rdn;
	}

	
	/*
	protected void printDNSources() {
    	
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
    	}cnUniqueIDSources
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
	*/
		
}
