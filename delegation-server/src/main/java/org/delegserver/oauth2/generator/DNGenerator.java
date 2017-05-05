package org.delegserver.oauth2.generator;

import java.net.IDN;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
//import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.bouncycastle.util.Arrays;
import org.delegserver.oauth2.shib.ShibAttrParser;
import org.delegserver.oauth2.shib.filters.ShibAttributeFilter;
import org.delegserver.oauth2.util.HashingUtils;
import org.delegserver.storage.RDNElement;
import org.delegserver.storage.RDNElementPart;

import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

import com.ibm.icu.text.Transliterator;

/**
 * Utility class for generating partial user DNs. The parts of the user DN being created 
 * by this are the O (Organisation) and the CN (Common Name) RDNs. A resulting partial DN
 * has the following form:
 * <p>
 *  /O={organisation}/CN={cnName} {cnUniqueId} {cnSeqNr}
 * <p>
 * This utility class works according to the DN Generator sources provided in the configuration.
 * The RDN components {organisation},{cnName} and {cnUniqueId} each have a set of source 
 * attributes which are taken in sequential order of preference. Once an attribute is found 
 * from a ordered preference list it is then used.
 * <p>
 * For more details on how DNs are constructed consult the RCauth Policy Document
 * ( https://rcauth.eu/policy ) section 3.1.2.
 * 
 * @author "Tamás Balogh"
 * @see <a href="https://rcauth.eu/policy">https://rcauth.eu/policy</a>
 *
 */
public class DNGenerator {
	private final static Transliterator trans =
	    Transliterator.getInstance(	"Serbian-Latin/BGN;"+
					"Russian-Latin/BGN;"+
					"Greek-en_US/UNGEGN;"+
					"Any-Latin;"+
					"Latin-Ascii");

	/* DEFAULTS AND CONSTANTS */
	
	public static String O_DELIMITER = " ";
	public static String CN_DELIMITER = " ";
	
	public static String RDN_TRUNCATE_SIGN = "...";
	
	public static int RDN_MAX_SIZE = 64;
	public static int CN_DISPAY_NAME_MAX_SIZE = 43;	
	public static int CN_UNIQUE_ID_MAX_SIZE = 16;
	public static int CN_MAX_SEQUENCE_NR = 999;
	
	public static String DN_OPENSSL_FORMAT = "/O=%s/CN=%s"; 
	public static String DN_RFC2253_FORMAT = "CN=%s,O=%s"; 
	
	public static String DN_TYPE_OPENSSL = "openssl";
	public static String DN_TYPE_RFC2253 = "rfc2253";
	public static String DEFAULT_DN_TYPE = DN_TYPE_RFC2253;
	
	/* CONFIGURATION ATTRIBUTES */
	
	public String dnType = null;
	public String baseDNOpenSSL = null;
	public String baseDNRFC2253 = null;
	public String attributeName = null;
	
	/* ATTRIBUTE SOURCES */
	
	protected Object[] cnNameSources = null; 
	protected Object[] cnUniqueIDSources = null;
	protected Object[] orgSources = null;
	
	/* ATTRIBUTE FILTER */
	protected Map<String,ShibAttributeFilter> filters = null;
	
	/* OTHER */
	
	protected Charset defaultCharset = null;
	protected Logable logger = null;
	
	/* CONSTUCTOR */
	
	/**
	 * Creates a DN Generator object from the DN Generator source configuration. The provided 
	 * parameters are expected to be lists of {@link Object}s with elements being either a single 
	 * {@link String} source or a array {@link String[]} of sources. Single attributes are simply user as-is 
	 * ,while an array of attribute sources will produce a concatenated list of attribute values. 
 	 * 
	 * @param cnNameSources Attribute source list for {cnName}
	 * @param cnUniqueIDSources Attribute source list for {cnUniqueId} 
	 * @param orgSources Attribute source list for {organisation}
	 * @param filters Attribute filters to apply on individual attributes
	 * @param logger Logger for producing logs.
	 */
	public DNGenerator(Object[] cnNameSources, Object[] cnUniqueIDSources, Object[] orgSources, Map<String,ShibAttributeFilter> filters, Logable logger) {
		this.cnNameSources = cnNameSources;
		this.cnUniqueIDSources = cnUniqueIDSources;
		this.orgSources = orgSources;
		
		this.filters = filters;
		
		// create helper objects here so that we don't have to create separate instances 
		// in multiple methods whenever they are needed.
		this.defaultCharset = Charset.forName("UTF-8");
		
		// in case of no logger provided create a new one.
		
		if ( logger != null ) {
			this.logger = logger;
		} else {
			throw new GeneralException("Cannot create DNGenerator without a Logger!");
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
	
	public void setBaseDNOpenSSL(String bASE_DN_OPENSSL) {
		baseDNOpenSSL = bASE_DN_OPENSSL;
	}
	
	public void setBaseDNRFC2253(String bASE_DN_RFC2253) {
		baseDNRFC2253 = bASE_DN_RFC2253;
	}	
	
	public void setDnType(String dnType) {
		this.dnType = dnType;
	}
	
	public void setAttributeName(String attributeName) {
		this.attributeName = attributeName;
	}
	
	public String getAttributeName() {
		return attributeName;
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
	 * @param attributeMap User attribute for building the O RDN
	 * @return The constructed O {@link RDNElement} (without the '/O=' prefix!)
	 */
	public RDNElement getOrganisation(Map<String,Object> attributeMap) {
		
		logger.debug("GENERATING ORGANISATION (O)");
		
		// Pick out the attribute source from the predefined configuration which is present in the 
		// provided attributeMap. Throw and exception if no suitable source is found.
		
		String[] orgSourceAttrs = chooseAttrSource(orgSources,attributeMap);
		
		if ( orgSourceAttrs == null ) {
			throw new GeneralException("No suitable attribute found for building 'Organization' attribute!");
		}

		logger.debug("	- Attribute Sources: '" + getConcatenatedStrings(orgSourceAttrs) + "'");
		
		// Build the O RDN from the selected source attribute. Use the getProcessedAttr to 
		// process the attribute value before setting it in the RDN
		
		String origOrganisation = null;
		for (String source : orgSourceAttrs) {
			if ( origOrganisation == null ) {
				origOrganisation = getProcessedAttr(attributeMap, source);
			} else {
				origOrganisation += O_DELIMITER + getProcessedAttr(attributeMap, source);
			}
		}

		logger.debug("	- Attribute Value: '" + origOrganisation + "'");		
		
		// Do some post-processing on the created RDN: 
		
		// convert to IDN (ASCII)
		String organisation = getPrintableString(origOrganisation);

		logger.debug("	- Attribute Value (after printable string conversion): '" + organisation + "'");		

		// truncate to appropriate length
		organisation = truncate(organisation, RDN_MAX_SIZE);
		
		logger.debug("	- Attribute Value (after truncating): '" + organisation + "'");		

		// escape slashes 
		organisation = organisation.replaceAll("/", "\\\\/");
		
		logger.debug("	- Generated Organisation (O): '" + organisation + "'");
		
		RDNElementPart orgPart = new RDNElementPart(organisation, origOrganisation, getConcatenatedStrings(orgSourceAttrs));
		RDNElement org = new RDNElement(organisation);
		org.addRDNElementPart(orgPart);
		
		return org;
	}

	/**
	 * Build the Common Name (CN) RDN from a set of input attributes, following the RCauth Policy Document
	 * ( https://rcauth.eu/policy ) section 3.1.2. This RDN is expected to be built from one of the 
	 * attribute sources defined under 'cnName' followed by a unique identifier from 'cnUniqueId'
	 * in the 'dnGenerator' configuration. 
	 * 
	 * In case no appropriate source attributes are found the the provided map, an exception
	 * will be thrown. 
	 * 
	 * @param attributeMap User attribute for building the CN RDN
	 * @return The constructed CN {@link RDNElement} (without the '/CN=' prefix!)
	 */
	public RDNElement getCommonName(Map<String,Object> attributeMap) {
		
		logger.debug("GENERATING CN");
		
		// First deal with the display name part of the common name
		RDNElementPart diplayName = getCommonNameDisplayPart(attributeMap);

		// Now deal with the uniqueness part of the CN
		RDNElementPart uniqueID = getCommonNameUniquePart(attributeMap);

		// the combination returned here should always be <= 64 
		String cn = diplayName.getElement() + CN_DELIMITER + uniqueID.getElement();
		
		logger.debug("	- Generated Common Name (CN): '" + cn + "'");
		
		// do a last size check to see that the length is within the allowed RDN size
		if ( cn.getBytes().length > RDN_MAX_SIZE ) {
			throw new GeneralException("CommonName exceeds the RDN_MAX_SIZE= " + RDN_MAX_SIZE);
		}
		
		RDNElement commonName = new RDNElement(cn);
		commonName.addRDNElementPart(diplayName);
		commonName.addRDNElementPart(uniqueID);
		
		return commonName;
	}
	 
	/**
	 * Build the Common Name (CN) RDN from a set of input attributes, with an appended sequence number {cnSeqNr}.
	 * 
	 * @param attributeMap User attribute for building the CN RDN
	 * @param sequenceNr Sequence number to append to the CN
	 * @return The constructed CN {@link RDNElement} (without the '/CN=' prefix!)
	 */
	public RDNElement getCommonName(Map<String,Object> attributeMap, int sequenceNr) {
		
		logger.debug("GENERATING CN WITH SEQUENCE NR");
		
		// check if the sequence number is in a valid range.
		if ( sequenceNr <= 0 || sequenceNr > CN_MAX_SEQUENCE_NR ) {
			throw new GeneralException("The index " + sequenceNr + " is not an acceptable value! Sequence number"
					+ "out of range ( 1 - " + CN_MAX_SEQUENCE_NR + " )" );
		}
		
		logger.debug("	- Appending sequence number: '" + sequenceNr + "'");
		
		// build CN and append sequence number to it
		RDNElement commonName = getCommonName(attributeMap);
		String cn = commonName.getElement() + CN_DELIMITER + sequenceNr;
		
		logger.debug("	- Generated Common Name (CN): '" + cn + "'");
		
		// do a last size check to see that the length is within the allowed RDN size
		if ( cn.getBytes().length > RDN_MAX_SIZE ) {
			throw new GeneralException("CommonName exceeds the RDN_MAX_SIZE= " + RDN_MAX_SIZE);
		}
		
		return commonName;
	}
	
	/**
	 * Build a list of all possible Common Name (CN) RDNs that can be derived from a set of user attributes.
	 * The resulting CNs all share the same {cnName} display name part of the CN which is created once using
	 * {{@link #getCommonNameDisplayPart(Map)}. The {cnUniqueId} on the other hand will be created using 
	 * every available unique ID attribute source (without any order of preference). A unique ID attribute 
	 * source is considered to be available if it is present as a key in the attributeMap provided.
	 * 
	 * @param attributeMap User attribute for building the CNs 
	 * @return A list of possible CN {@link RDNElement}s with different {cnUniqueId}s
	 */
	public List<RDNElement> getCommonNames(Map<String,Object> attributeMap) {
		
		logger.debug("GENERATING LIST OF POSSIBLE CNs");
		
		// The list of resulting CNs
		List<RDNElement> cns = new ArrayList<RDNElement>();
		
		// First deal with the display name part of the common name. This will be the same for every 
		// CN constructed below.
		RDNElementPart diplayName = getCommonNameDisplayPart(attributeMap);
		
		// Take every unique ID attribute source and construct a single CN
		for(Object obj : cnUniqueIDSources) {
			
			// get the unique ID source name (or names in case of a multi valued element)
			String[] uniqueIDSourceAttr;
			if ( obj instanceof String[] ) {
				uniqueIDSourceAttr = (String[]) obj;
			} else {
				uniqueIDSourceAttr = new String[1];
				uniqueIDSourceAttr[0] = (String) obj;
			}
			
			logger.debug("	- Unique ID Attribute Sources: '" + getConcatenatedStrings(uniqueIDSourceAttr) + "'");
			
			// construct a concatenated list of attributes based on the attributes chosen above.
			String origUniqueID = null;
			for (String source : uniqueIDSourceAttr) {
				
				if ( ! attributeMap.containsKey(source) ) {
					// in case a source attribute is missing, simply ignore this source set and move on to the next one.
					// This is not an error, it simply means that the IdP is not releasing a particular unique id.
					logger.debug("	- Unique ID Attribute Sources: '" + source + "' not found attribute map. ignoring..." );
					origUniqueID = null;
					break;
				}
				
				// construct a concatenated list of attribute values
				if ( origUniqueID == null ) {
					origUniqueID = getProcessedAttr(attributeMap, source);
				} else {
					origUniqueID += CN_DELIMITER + getProcessedAttr(attributeMap, source);
				}
			}
			
			// in case the unique id is empty (one of its source attributes was missing from the user attribute map)
			// simply move on to the next set of sources.
			if ( origUniqueID == null ) {		
				continue;				
			}
			
			// postprocess CN
			
			logger.debug("	- Unique ID Attribute Value: '" + origUniqueID + "'");
			
			// create Unique Shortened Representation
			String uniqueID = getUSR(origUniqueID);
			
			logger.debug("	- Unique ID Attribute Value (after USR conversion): '" + uniqueID + "'");
			
			// the combination returned here should always be <= 64 
			String cn = diplayName.getElement() + CN_DELIMITER + uniqueID;
			
			logger.debug("	- Generated Common Name (CN): '" + cn + "'");			
			
			// do a last size check to see that the length is within the allowed RDN size
			if ( cn.getBytes().length > RDN_MAX_SIZE ) {
				throw new GeneralException("CommonName exceeds the RDN_MAX_SIZE= " + RDN_MAX_SIZE);
			}
			
			RDNElementPart uniquePart = new RDNElementPart(uniqueID, origUniqueID, getConcatenatedStrings(uniqueIDSourceAttr));
			RDNElement commonName = new RDNElement(cn);
			commonName.addRDNElementPart(diplayName);
			commonName.addRDNElementPart(uniquePart);
			
			cns.add(commonName);
			
		}
		
		logger.debug("	- Possible Common Names (CNs) generated: " + cns.size());
		
		// check if we got any CNs at all. 
		if ( cns.isEmpty() ) {
			throw new GeneralException("Could not build ANY CNs! Check that you attribute sources are correct!");			
		}
		
		return cns;
	}
	
	/**
	 * Build the {cnName} display name part of the DN from a set of input attributes
	 * 
	 * @param attributeMap User attribute for building the CN RDN
	 * @return The display name part of the DN inside a {@link RDNElementPart} 
	 */
	public RDNElementPart getCommonNameDisplayPart(Map<String,Object> attributeMap) {

		logger.debug("GENERATING DISPLAY NAME PART OF CN");
		
		// choose the first set of sources from an ordered list of preference which is 
		// present in the provided user attributes.
		String[] cnNameSourceAttr = chooseAttrSource(cnNameSources,attributeMap);
		if ( cnNameSourceAttr == null ) {
			throw new GeneralException("No suitable attribute found for building the Display Name part of the 'CommonName' attribute!");
		}		
		
		logger.debug("	- Display Name Attribute Sources: '" + getConcatenatedStrings(cnNameSourceAttr) + "'");

		// Build the {cnName} display name part of the DN from the selected source attribute. 
		// Use the {@link #getProcessedAttr} to process the attribute value before setting it in the RDN		
		
		String origDisplayName = null;
		for (String source : cnNameSourceAttr) {
			if ( origDisplayName == null ) {
				origDisplayName = getProcessedAttr(attributeMap, source);
			} else {
				origDisplayName += CN_DELIMITER + getProcessedAttr(attributeMap, source);
			}
		}
		
		// do some postprocessing
		
		logger.debug("	- Display Name Attribute Value: '" + origDisplayName + "'");
		
		// convert to printable string
		
		String diplayName = getPrintableString(origDisplayName);
		
		logger.debug("	- Display Name Attribute Value (after printable string conversion): '" + diplayName + "'");		
		
		// truncate to the right size
		
		diplayName = truncate(diplayName,CN_DISPAY_NAME_MAX_SIZE);
		
		logger.debug("	- Display Name Attribute Value (after truncating): '" + diplayName + "'");
		
		return new RDNElementPart(diplayName, origDisplayName, getConcatenatedStrings(cnNameSourceAttr));
	}
	
	/**
	 * Build the {cnUniqueId} unique ID part of the DN from a set of input attributes
	 * 
	 * @param attributeMap User attribute for building the CN RDN
	 * @return The unique ID part of the DN inside a {@link RDNElementPart}
	 */
	public RDNElementPart getCommonNameUniquePart(Map<String,Object> attributeMap) {
	
		logger.debug("GENERATING UNIQUE ID PART OF CN");
		
		// choose the first set of sources from an ordered list of preference which is 
		// present in the provided user attributes.		
		String[] uniqueIDSourceAttr = chooseAttrSource(cnUniqueIDSources,attributeMap);
		if ( uniqueIDSourceAttr == null ) {
			throw new GeneralException("No suitable attribute found for building the Unique ID part of the 'CommonName' attribute!");			
		}
		
		logger.debug("	- Unique ID Attribute Sources: '" + getConcatenatedStrings(uniqueIDSourceAttr) + "'");
		
		// Build the {cnUniqueId} unique ID part of the DN from the selected source attribute. 
		// Use the {@link #getProcessedAttr} to process the attribute value before setting it in the RDN			
		
		String origUniqueID = null;
		for (String source : uniqueIDSourceAttr) {
			if ( origUniqueID == null ) {
				origUniqueID = getProcessedAttr(attributeMap, source);
			} else {
				origUniqueID += CN_DELIMITER + getProcessedAttr(attributeMap, source);
			}
		}
		
		logger.debug("	- Unique ID Attribute Value: '" + origUniqueID + "'");
		
		// do some postprocessing
		
		// convert into USR
		String uniqueID = getUSR(origUniqueID);
		
		logger.debug("	- Unique ID Attribute Value (after USR conversion): '" + uniqueID + "'");	
		
		return new RDNElementPart(uniqueID, origUniqueID, getConcatenatedStrings(uniqueIDSourceAttr));
	}
	
	/* DN FORMATTING METHODS */
	
	public String formatDNSufix(String org,String cn) {
		String dn =  String.format(DN_OPENSSL_FORMAT, org, cn);
		
		logger.debug("	- Generated Distinguished Name (DN): '" + dn + "'");
		
		return dn;		
	}
	
	public String formatDNSufix(String org, String cn, int sequenceNr) {
		
		validateSequenceNr(sequenceNr);
		
		if ( sequenceNr == 0 ) {
			return formatDNSufix(org, cn);
		}
		
		String dn =  String.format(DN_OPENSSL_FORMAT, org, cn + CN_DELIMITER + sequenceNr);
		
		logger.debug("	- Generated Distinguished Name (DN): '" + dn + "'");
		
		return dn;		
	}	
	
	public String formatToOpenSSL(String org, String cn, int sequenceNr) {
		
		if ( baseDNOpenSSL == null || baseDNOpenSSL.isEmpty() ) {
			throw new GeneralException("Cannot create full DN in openssl format without the base dn!");
		}
 		
		if ( baseDNOpenSSL.endsWith("/") ) {
			return baseDNOpenSSL + formatDNSufix(org, cn, sequenceNr).substring(1); 
		} else {
			return baseDNOpenSSL + formatDNSufix(org, cn, sequenceNr);
		}
		
	}
	
	public String formatToRFC2253(String org, String cn, int sequenceNr) {
		
		if ( CN_DELIMITER == null || CN_DELIMITER.isEmpty() ) {
			throw new GeneralException("Cannot create full DN in RFC2253 format without the base dn!");
		}
		
		validateSequenceNr(sequenceNr);
		
		if ( sequenceNr > 0 ) {
			cn += CN_DELIMITER + sequenceNr;
		}
		
		return String.format(DN_RFC2253_FORMAT, cn , org) + "," + baseDNRFC2253;

	}
	
	public String formatFullDN(String org, String cn, int sequenceNr) {
		
		String format = null;
		if ( dnType != null && ! dnType.isEmpty()) {
			format  = dnType;
		} else {
			format = DEFAULT_DN_TYPE;
		}
			
		if ( format.equals( DN_TYPE_OPENSSL ) ) {
			return formatToOpenSSL(org, cn, sequenceNr);
		} else if ( format.equals( DN_TYPE_RFC2253 ) ) {
			return formatToRFC2253(org, cn, sequenceNr);
		}
		
		throw new GeneralException("Unsupported DN formatting '" + format  + "'");
	}
	
	
	/* HELPER METHODS */
	
	/**
	 * Validate a sequence number. It will be checked against a valid range of
	 * [0..{@link CN_MAX_SEQUENCE_NR}]. An exception is thrown in case the 
	 * number is not valid.
	 * 
	 * @param sequenceNr The number to validate
	 */
	protected void validateSequenceNr(int sequenceNr) {
		
		// check if the sequence number is in a valid range.
		if ( sequenceNr < 0 || sequenceNr > CN_MAX_SEQUENCE_NR ) {
			throw new GeneralException("The index " + sequenceNr + " is not an acceptable value! Sequence number"
					+ "out of range ( 1 - " + CN_MAX_SEQUENCE_NR + " )" );
		}
	}
	
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
	    
	    logger.debug("	- CONVERTING TO PRINTABLE STRING");
	    logger.debug("		- Source Input: '" + input + "'");

	    String output1 = trans.transliterate(input);

	    // PrintableString == \\p{Lower}\\p{Upper}\\p{Digit} '()+,-./:=?
	    // Remove /:= from set of PrintableString to prevent collisions with
	    // e.g. htaccess files and openssl strings. Do add @ for e.g. the
	    // igtf proxy which adds the ePPN to the displayName
	    String normalizedOutput = output1.replaceAll("[^\\p{Lower}\\p{Upper}\\p{Digit} '()+,-.?@]", "X");
	    
	    logger.debug("		- Printable String Equivalent: '" + normalizedOutput + "'");
	    
	    return normalizedOutput;
	}
	
	/**
	 * Create a Unique Shortened Representation (USR) from a source attribute string. The way
	 * a USR is constructed is outlined in the RCauth Policy Document ( https://rcauth.eu/policy ) 
	 * in section 3.1.2. 
	 * 
	 * The USR is the first 16 bytes of base64(sha256(attr)), with any SOLIDUS ("/") and plus ("+")
	 * characters replaced by HYPHEN-MINUS ("-") characters.
	 * 
	 * @param attr Input for the USR creation
	 * @return USR of the input attribute
	 */
	protected String getUSR(String attr) {
		
		logger.debug("	- GENERATING USR FOR ATTRIBUTE : '" + attr + "'");
		
		// get the base64 encoded SHA-256 hash of the input string 
		String encodedHashString = HashingUtils.getInstance().hashToBase64(attr);
		byte[] encodedHash =  encodedHashString.getBytes();
		logger.debug("		- Full Hashed Attribute: '" + encodedHashString + "'");
		
		// truncate the resulting base64 string to the required maximum size
		byte [] shortEncodedHash = Arrays.copyOf(encodedHash, CN_UNIQUE_ID_MAX_SIZE);
		String shortEncodedHashString = new String(shortEncodedHash);
		logger.debug("		- Shortened Hashed Attribute: '" + shortEncodedHashString + "'");
		
		// replace "/" and "+" with "-" 
		String finalEncodedHashString = shortEncodedHashString.replaceAll("/", "-");
		finalEncodedHashString = finalEncodedHashString.replaceAll(Pattern.quote("+"), "-");
		logger.debug("		- Shortened Hashed Attribute (after replacements): '" + finalEncodedHashString + "'");
		
		// alternatively we can also use substring since we cannot break any character encoding
		// within the base64 string cuz every character is one byte (right? (right?))
		//String shortEncodedHashString2 = finalEncodedHashString.substring(0, CN_UNIQUE_ID_MAX_SIZE);
		
		return finalEncodedHashString;
	}
	
	/**
	 * Select an Attribute Source from the attrSources provided. The selection will happen
	 * according to the predefined order of preference in attrSources. An attribute set 
	 * from attrSources is selected only in case all of its individual attributes are 
	 * present as keys in the provided user attributeMap.
	 * 
	 * @param attrSources Configured attribute sources in order of preference
	 * @param attributeMap User attribute map 
	 * @return Array of selected source set
	 */
	protected String[] chooseAttrSource(Object[] attrSources, Map<String,Object> attributeMap) {
		
		String[] selectedAttrSource = null;
		
		for ( Object obj : attrSources ) {
			
			// object from the attribute set can either be String or String[]
			
			if (obj instanceof String) {
				// single attribute 
				if ( attributeMap.containsKey((String)obj) ) {
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
    				if ( ! attributeMap.containsKey(s) ) {
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
	
	/**
	 * Process an attribute value before using it. This method is the perfect place to add custom rules of 
	 * single attributes which should be applied 
	 *  
	 * @param attributeMap User attribute map 
	 * @param attributeKey Attribute Key from the attributeMap
	 * @return The value of attributeKey from attributeMap after processing
	 */
	protected String getProcessedAttr(Map<String,Object> attributeMap, String attributeKey) {
		
		if ( attributeMap == null || attributeKey == null || ! attributeMap.containsKey(attributeKey) ) {
			return null;
		}
		
		Object attr = attributeMap.get(attributeKey);
		String attribute = null;
		
		if ( attr instanceof String ) {
			attribute = getFilteredAttribute(attributeKey, (String) attr);
		} else if ( attr instanceof List ) {
			logger.warn("Unexpected multiple values for attribute " + attributeKey);
			List<String> attrList = ((List<String>)attr);
			List<String> filteredList = new ArrayList<String>();
			
			// apply attribute filters on every value separately
			for ( String a : attrList ) {
				String filteredAttr =  getFilteredAttribute(attributeKey, a);
				// make a copy of the attributes in order to preserve the original form
				filteredList.add(filteredAttr);
			}
			
			attribute = ShibAttrParser.combineMultiValuedAttr( filteredList );
		} else {
			logger.error("Unexpected instance for attribute " + attributeKey +". Was expecting either String or List<String>");
			return null;			
		}

		return attribute;
	}
	
	/**
	 * Apply filters on a specific attribute. The attrKey determined which 
	 * filters should be applied (if any) on the attrValue. Returns the
	 * filtered attrValue. 
	 * 
	 * @param attrKey The key of the attribute
	 * @param attrValue The value of the attribute
	 * @return The filtered attribute value
	 */
	protected String getFilteredAttribute(String attrKey, String attrValue) {
		
		ShibAttributeFilter attributeFilter = filters.get(attrKey);
		
		if ( attributeFilter != null ) {
			
			logger.debug("		- Applying filter '" + attributeFilter.getClass().getCanonicalName() + "' for attribute : '" + attrValue + "'");
			attrValue = attributeFilter.process(attrValue);
			logger.debug("		- Attribute after filter : '" + attrValue + "'");
		
		}
		return attrValue;
	}
	
	/**
	 * Implementation of the general truncating rule outlined in the RCauth Policy Document
	 * ( https://rcauth.eu/policy ) in section 3.1.2. It takes an RDN as input and checks its
	 * UTF-8 encoded byte size. In case it's larger than the size provided in the parameters,
	 * the RDN will get truncated to 61 UTF-8 bytes (or less in case the bordering byte is 
	 * in the middle of a UTF-8 character definition) with RDN_TRUNCATE_SIGN appended to the
	 * end.
	 * 
	 * @param rdn Input RDN to be truncated in case it's too large 
	 * @param size The size to which the RDN should be truncated. This value defaults to 
	 * RDN_MAX_SIZE (64 bytes) in case the size provided is less then or equal to 0 
	 * @return Truncated RDN 
	 */
	protected String truncate(String rdn,int size) {
		
		if ( size <= 0 ) {
			size = RDN_MAX_SIZE;
		}

		
		// only truncate if the RDN exceeds the maximum allowed size
		if ( rdn.getBytes(defaultCharset).length > size ) {

			logger.debug("	- TRUNCATING RDN to " + size + " bytes");

			logger.debug("		- Source RDN : '" + rdn + "'");
			
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
			
			logger.debug("		- Truncated Form : '" + rdn + "'");
			
		}
		
		return rdn;
	}

	/* METHODS USER FOR DEBUGGING AND DISPLAY */
	
	private String getConcatenatedStrings(String[] collection) {
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
