package org.delegserver.oauth2.generator;

import java.io.UnsupportedEncodingException;
import java.net.IDN;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.MapUtils;
import org.bouncycastle.util.Arrays;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

public class DNGenerator {

	/* DEFAULTS AND CONSTANTS */
	
	public static String O_DELIMITER = " ";
	public static String CN_DELIMITER = " ";
	
	public static String RDN_TRUNCATE_SIGN = "...";
	
	public static int RDN_MAX_SIZE = 64;
	public static int CN_DISPAY_NAME_MAX_SIZE = 43;	
	public static int CN_UNIQUE_ID_MAX_SIZE = 16;
	public static int CN_MAX_SEQUENCE_NR = 999;
	
	public static String DN_FORMAT = "/O=%s/CN=%s"; 

	/* ATTRIBUTE SOURCES */
	
	protected Object[] cnNameSources = null; 
	protected Object[] cnUniqueIDSources = null;
	protected Object[] orgSources = null;
	
	/* OTHER */
	
	protected Charset defaultCharset = null;
	protected MessageDigest defaultMessageDigest = null;
	protected MyLoggingFacade logger = null;;
	
	public DNGenerator(Object[] cnNameSources, Object[] cnUniqueIDSources, Object[] orgSources, MyLoggingFacade logger) {
		this.cnNameSources = cnNameSources;
		this.cnUniqueIDSources = cnUniqueIDSources;
		this.orgSources = orgSources;
		
		this.defaultCharset = Charset.forName("UTF-8");
		try {
			this.defaultMessageDigest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new GeneralException("Unable to create default message digest SHA-256",e);
		}
		
		if ( logger != null ) {
			this.logger = logger;
		} else {
			this.logger = new MyLoggingFacade(this.getClass().getCanonicalName());
		}
	}
	
	/* SIMPLE GETTERS AND SETTERS */
	
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
	public String getOrganisation(Map<String,String> attributeMap) {
		
		logger.info("CREATING ORGANISATION (O) ATTRIBUTE");
		
		// Pick out the attribute source from the predefined configuration which is present in the 
		// provided attributeMap. Throw and exception if no suitable source is found.
		
		String[] orgSourceAttrs = chooseAttrSource(orgSources,attributeMap);
		
		if ( orgSourceAttrs == null ) {
			throw new GeneralException("No suitable attribute found for building 'Organization' attribute!");
		}

		logger.info("	- Attribute Sources: '" + getConcatenatedStrings(orgSourceAttrs) + "'");
		
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

		logger.info("	- Attribute Value: '" + organisation + "'");		
		
		// Do some post-processing on the created RDN: 
		// 		- convert to IDN (ASCII)
		//		- truncate to appropriate length
		
		organisation = getIDNString(organisation);

		logger.info("	- Attribute Value (after printable string conversion): '" + organisation + "'");		
		
		organisation = truncate(organisation, RDN_MAX_SIZE);
		
		logger.info("	- Attribute Value (after truncating): '" + organisation + "'");		

		logger.info("	- Generated Organisation (O): '" + organisation + "'");
		
		return organisation;
	}

	public String getCommonName(Map<String,String> attributeMap) {
		
		logger.info("COMMON NAME (CN) ATTRIBUTE");
		
		// First deal with the display name part of the common name
		String diplayName = getCommonNameDisplayPart(attributeMap);

		// Now deal with the uniqueness part of the CN
		String uniqueID = getCommonNameUniquePart(attributeMap);

		// the combination returned here should always be <= 64 
		String cn = diplayName + CN_DELIMITER + uniqueID;
		
		logger.info("	- Generated Common Name (CN): '" + cn + "'");
		
		return cn;
	}
	
	public String getCommonName(Map<String,String> attributeMap, int index) {
		
		if ( index <= 0 || index > CN_MAX_SEQUENCE_NR ) {
			throw new GeneralException("The index " + index + " is not an acceptable value! Sequence number"
					+ "out of range ( 1 - " + CN_MAX_SEQUENCE_NR + " )" );
		}
		
		String rdn = getCommonName(attributeMap) + CN_DELIMITER + index;
		
		if ( rdn.getBytes().length > RDN_MAX_SIZE ) {
			throw new GeneralException("CommonName exceeds the RDN_MAX_SIZE(64)!");
		}
		
		return rdn;
	}
	
	public List<String> getCommonNames(Map<String,String> attributeMap) {
		
		List<String> cns = new ArrayList<String>();
		
		// First deal with the display name part of the common name
		String diplayName = getCommonNameDisplayPart(attributeMap);
		
		for(Object obj : cnUniqueIDSources) {
			
			String[] uniqueIDSourceAttr;
			if ( obj instanceof String[] ) {
				uniqueIDSourceAttr = (String[]) obj;
			} else {
				uniqueIDSourceAttr = new String[1];
				uniqueIDSourceAttr[0] = (String) obj;
			}
			
			logger.info("	- Unique ID Attribute Sources: '" + getConcatenatedStrings(uniqueIDSourceAttr) + "'");
			
			String uniqueID = null;
			for (String source : uniqueIDSourceAttr) {
				
				if ( ! attributeMap.containsKey(source) ) {
					logger.info("	- Unique ID Attribute Sources: '" + source + "' not found attribute map. ignoring..." );
					uniqueID = null;
					break;
				}
				
				if ( uniqueID == null ) {
					uniqueID = getProcessedAttr(attributeMap, source);
				} else {
					uniqueID += CN_DELIMITER + getProcessedAttr(attributeMap, source);
				}
			}
			
			if ( uniqueID == null ) {		
				continue;				
			}
			
			logger.info("	- Unique ID Attribute Value: '" + uniqueID + "'");
			
			uniqueID = getUSR(uniqueID);
			
			logger.info("	- Unique ID Attribute Value (after USR conversion): '" + uniqueID + "'");
			
			// the combination returned here should always be <= 64 
			String cn = diplayName + CN_DELIMITER + uniqueID;
			
			logger.info("	- Generated Common Name (CN): '" + cn + "'");			
			
			cns.add(cn);
		}
		
		if ( cns.isEmpty() ) {
			throw new GeneralException("Could not build ANY CN! Chech that you attribute sources are correct!");			
		}
		
		return cns;
	}
	
	public String getCommonNameDisplayPart(Map<String,String> attributeMap) {
		
		String[] cnNameSourceAttr = chooseAttrSource(cnNameSources,attributeMap);
		if ( cnNameSourceAttr == null ) {
			throw new GeneralException("No suitable attribute found for building the Display Name part of the 'CommonName' attribute!");
		}		
		
		logger.info("	- Display Name Attribute Sources: '" + getConcatenatedStrings(cnNameSourceAttr) + "'");
		
		String diplayName = null;
		for (String source : cnNameSourceAttr) {
			if ( diplayName == null ) {
				diplayName = getProcessedAttr(attributeMap, source);
			} else {
				diplayName += CN_DELIMITER + getProcessedAttr(attributeMap, source);
			}
		}
		
		logger.info("	- Display Name Attribute Value: '" + diplayName + "'");
		
		diplayName = getPrintableString(diplayName);
		
		logger.info("	- Display Name Attribute Value (after printable string conversion): '" + diplayName + "'");		
		
		diplayName = truncate(diplayName,CN_DISPAY_NAME_MAX_SIZE);
		
		logger.info("	- Display Name Attribute Value (after truncating): '" + diplayName + "'");
		
		return diplayName;
	}
	
	public String getCommonNameUniquePart(Map<String,String> attributeMap) {
		
		String[] uniqueIDSourceAttr = chooseAttrSource(cnUniqueIDSources,attributeMap);
		if ( uniqueIDSourceAttr == null ) {
			throw new GeneralException("No suitable attribute found for building the Unique ID part of the 'CommonName' attribute!");			
		}
		
		logger.info("	- Unique ID Attribute Sources: '" + getConcatenatedStrings(uniqueIDSourceAttr) + "'");
		
		String uniqueID = null;
		for (String source : uniqueIDSourceAttr) {
			if ( uniqueID == null ) {
				uniqueID = getProcessedAttr(attributeMap, source);
			} else {
				uniqueID += CN_DELIMITER + getProcessedAttr(attributeMap, source);
			}
		}
		logger.info("	- Unique ID Attribute Value: '" + uniqueID + "'");
		
		uniqueID = getUSR(uniqueID);
		
		logger.info("	- Unique ID Attribute Value (after USR conversion): '" + uniqueID + "'");	
		
		return uniqueID;
	}
	
	
	public String getUserDNSufix(Map<String,String> attributeMap) {
		
		String org = getOrganisation(attributeMap);
		String cn = getCommonName(attributeMap);
		
		String dn =  String.format(DN_FORMAT, org, cn);
		
		logger.info("	- Generated Distingueshed Name (DN): '" + dn + "'");
		
		return dn;
	}
	
	/* HELPER METHODS */
	
	/**
	 * Convert the provided input into a Printable String version. A 'normalization' will
	 * be attempted first on every character (remove accents). In case a character cannot 
	 * be 'normalized' it will be completely replaces by 'X', according to the RCAuth 
	 * Policy Document ( https://rcauth.eu/policy ) in section 3.1.2. 
	 * 
	 * @param input The name to be converted to printable string
	 * @return Printable string representation of the provided input
	 */
	protected String getPrintableString(String input) {
		
		String normalizedOutput = "";
		
		// take unicode characters one by one and normalize them
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			// normalize a single unicode character, then remove every non-ascii symbol (like
			// accents) 
			String normalizedChar = Normalizer.normalize(String.valueOf(c) , Normalizer.Form.NFD)
					                          .replaceAll("[^\\p{ASCII}]", "");
			
			if ( ! normalizedChar.isEmpty() ) {
				// if there is a valid ascii representation, use it
				normalizedOutput += normalizedChar;
			} else {
				// otherwise replace character with an "X"
				normalizedOutput += "X";
			}
		}
		
		return normalizedOutput;
	}
	
	/**
	 * Get an IDN printable string equivalent of the input. This method should be used to convert 
	 * hostnames (like the ones set in schacHomeOrganisation) into printable strings
	 * 
	 * @param input The hostname to convert
	 * @return Converted printable ascii string   
	 */
	protected String getIDNString(String input) {
		return IDN.toASCII(input);
	}
	
	/**
	 * Create a Unique Shortened Representation (USR) from a source attribute string. The way
	 * a USR is constructed is outlined in the RCauth Policy Document ( https://rcauth.eu/policy ) 
	 * in section 3.1.2. 
	 * 
	 * The USR is the first 16 bytes of base64(sha256(attr)), with any SOLIDUS (“/”) characters 
	 * replaced by HYPHEN-MINUS (“-“) characters.
	 * 
	 * @param attr Input for the USR creation
	 * @return USR of the input attribute 
	 * @throws NoSuchAlgorithmException 
	 * @throws UnsupportedEncodingException 
	 */
	protected String getUSR(String attr) {
		
		// get the SHA-256 hash of the input string 
		byte[] hash = defaultMessageDigest.digest( attr.getBytes(defaultCharset) );
		
		// get the base64 encoding of the hash from the previous step
		byte[] encodedHash =  Base64.encodeBase64(hash);
		String encodedHashString = new String(encodedHash);

		// replace "/" with "-" 
		String finalEncodedHashString = encodedHashString.replaceAll("/", "-");
		
		// truncate the resulting base64 string to the required maximum size
		byte [] shortEncodedHash = Arrays.copyOf(encodedHash, CN_UNIQUE_ID_MAX_SIZE);
		String shortEncodedHashString = new String(shortEncodedHash).replaceAll("/", "-");
		
		// alternatively we can also use substring since we cannot break any character encoding
		// within the base64 string cuz every character is one byte (right? (right?))
		String shortEncodedHashString2 = finalEncodedHashString.substring(0, CN_UNIQUE_ID_MAX_SIZE);
		
		//TODO: log mapping of full encoded hash and the first 16 bytes of the encoded hash
		System.out.println(" ===================================================== ");
		System.out.println(" ORIGINAL attribute = " + attr);
		System.out.println(" FULL encoded hash = " + encodedHashString);
		System.out.println(" FULL encoded hash (after replace) = " + finalEncodedHashString);
		System.out.println(" SHORTENED encoded hash = " + shortEncodedHashString);
		System.out.println(" ===================================================== ");
		
		return shortEncodedHashString;
	}
	
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
	protected String truncate(String rdn,int size) {
		
		if ( size <= 0 ) {
			size = RDN_MAX_SIZE;
		}
		
		// only truncate if the RDN exceeds the maximum allowed size
		if ( rdn.getBytes(defaultCharset).length > size ) {
		
			int truncatedSize = size - RDN_TRUNCATE_SIGN.getBytes(defaultCharset).length;
			
			CharsetDecoder cd = defaultCharset.newDecoder();
			byte[] sba = rdn.getBytes(defaultCharset);
			
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

	protected String getConcatenatedStrings(String[] collection) {
		String bundle = null;
		for ( String s : collection ) {
			if ( bundle == null ) {
				bundle = s;
			} else {
				bundle += " " + s;
			}
		}
		return bundle;
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
