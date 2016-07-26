package org.delegserver.oauth2.generator;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.delegserver.oauth2.exceptions.IncompleteAttributeSetException;
import org.delegserver.oauth2.shib.ShibAttrParser;
import org.delegserver.oauth2.util.HashingUtils;
import org.delegserver.storage.TraceRecord;

import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * Utility class for building and matching unique attribute lists. A Unique Attribute List is 
 * a set of attributes that are used together (in form of a hash) to distinguish one user
 * from another. This Unique Attribute List is generated using an Attribute Source List 
 * from the server configuration and a set of User Attributes release by an IdP. 
 * <p>
 * For more details on how Unique Attribute List are constructed consult the RCauth Policy Document
 * ( https://rcauth.eu/policy ) section 3.1.2.
 * 
 * @author "Tamás Balogh"
 * @see <a href="https://rcauth.eu/policy">https://rcauth.eu/policy</a>
 */
public class UniqueAttrGenerator {

	public static String ATTRIBUTE_SEPARATOR = ",";
	
	protected String[] uniqueAttrSources = null;
	protected String uniqueAttrSourceList = "";
	
	protected Logable logger = null;
	
	/* SINGLETON CONSTRUCTOR */
	
	/**
	 * Create A Unique Attribute Generator based on a set of attribute sources. 
	 * 
	 * @param attrSources Attribute Sources 
	 * @param logger The logger class
	 */
	public UniqueAttrGenerator(String[] attrSources, Logable logger) {
		this.uniqueAttrSources = attrSources;
		
		for ( String source : uniqueAttrSources ) {
			uniqueAttrSourceList = ( uniqueAttrSourceList.isEmpty() ) ? source : "," + source; 
		}
		
		if ( logger != null ) {
			this.logger = logger;
		} else {
			throw new GeneralException("Cannot create UniqueAttrGenerator without a Logger!");
		}
	}
	
	/* CHECKER METHODS */
	
	
	/**
	 * Match user with a trace record. The user here is identified by the attribute map attributeMap.  
	 * <p>
	 * An attribute list if build from the user attributeMap, taking only the attributes which 
	 * were saved in the traceRecrod. This attribute list is then salted (with the salt from traceRecord)
	 * and hashed. The resulting hash is compared with the attribute hash stored under the traceRecord.
	 * In case these hashes match, this method returns true, otherwise it returns false.
	 * 
	 * @param attributeMap User attribute map to match
	 * @param traceRecord Trace record to match against 
	 * @return true if hashes are the same, false otherwise.
	 * @throws IncompleteAttributeSetException When an attribute that was previously used to compute the hash disappears
	 */
	public boolean matches(Map<String,Object> attributeMap, TraceRecord traceRecord) throws IncompleteAttributeSetException {
		
		logger.debug("START ATTRIBUTE MATCHING" );
		logger.debug("	- Comparing attribute map with Trace Record: '" + traceRecord.getCnHash() + "'");
		
		
		// build attribute list using the attribute names in the traceRecords previously stored
		
		String attrList = null;		
		for (String attrSource : traceRecord.getAttrNames()) {
			if ( attributeMap.containsKey(attrSource) ) {
				
				if ( attrList == null ) {
					attrList = getProcessedAttr(attributeMap, attrSource);
				} else {
					attrList += ATTRIBUTE_SEPARATOR + getProcessedAttr(attributeMap, attrSource);	
				}
				
			} else {

				logger.debug( "	- Attribute " + attrSource + " not found!" );
				logger.debug( "	- Mismatch between stored attributes and present attributes" );
				
				// mismatch between the attributes saved and attributes present in the attributeMap 
				// (when an attribute which was previously used to construct the hash is missing,
				//  we can be sure that the attribute list hashes will not be the same)
				throw new IncompleteAttributeSetException("Change in last seen user attribute! Missing attribute '" + attrSource + "'!");
			}
		}

		logger.debug( "	- Attribute List Computed : '" + attrList + "'");

		// salt and hash attribute list with the same salt used in the trace records
		
		byte[] salt = Base64.decodeBase64( traceRecord.getAttrSalt() );
		
		logger.debug( "	- Salt (RAW) Extracted for Attribute List Hash : '" + traceRecord.getAttrSalt()  + "'");
		
		String attrHash = HashingUtils.getInstance().saltedHashToBase64( attrList , salt );

		logger.debug( "	- Attribute Hash Computed : '" + attrHash + "'");		
		
		// now for the moment of truth. compare the attribute hash we built with the one previously stored
		
		logger.debug( "	- Expecting Attribute Hash from Trace Record : '" + traceRecord.getAttrHash() + "'");
		
		if ( attrHash.equals( traceRecord.getAttrHash() ) ) {
			
			logger.debug( "	- Attribute Hash Computed matches Stored Attribute Hash");	
			
			// attribute hash is matching!
			return true;
		} else {
			// attribute hash is not matching! this effectively means that (at least) one of the stored attribute 
			// has a different value than it had before! It is impossible to say which tho.

			logger.debug( "Attribute Hash Computed does NOT match Stored Attribute Hash");	
			
			return false;
		}
	}
	
	/* BUILDER METHODS */
	
	/**
	 * Build a concatenated list of Unique Attributes. This list should be unique for ever user.
	 * If a source attribute list will get traversed in its predefined order, and attributes 
	 * will get extracted from the input attributeMap. If an attribute is missing from the 
	 * input map we simply ignore it.
	 * <p>
	 * The results of this method should match the values of the Uniqueness Attribute Names returned by 
	 * {@link #getUniqueAttributeNames(Map)}
	 *
	 * @param attributeMap User attribute map
	 * @return A concatenated list of Unique Attributes
	 */
	public String getUniqueAttributes(Map<String,Object> attributeMap) {
		
		String attrList = null;		
		
		// iterate over the source attributes 
		for (String attrSource : uniqueAttrSources) {
			if ( attributeMap.containsKey(attrSource) ) {
				// if an attribute is present in the user map, add it to the list
				if ( attrList == null ) {
					attrList = getProcessedAttr(attributeMap, attrSource);
				} else {
					attrList += ATTRIBUTE_SEPARATOR + getProcessedAttr(attributeMap, attrSource);;		
				}
			}
			// if an attribute is missing from the map we simply ignore it
		}
		
		return attrList;
	}
	
	protected String getProcessedAttr(Map<String,Object> attributeMap, String attributeKey) {

		Object attr = attributeMap.get(attributeKey);
		String attribute = null;
		if ( attr instanceof String ) {
			attribute = (String) attr;
		} else if ( attr instanceof List ) {
			logger.warn("Unexpected multiple values for attribute " + attributeKey);
			List<String> attrs = ((List<String>)attr);
			attribute = ShibAttrParser.combineMultiValuedAttr( attrs );
		} else {
			logger.error("Unexpected instance for attribute " + attributeKey +". Was expecting either String or List<String>");
			return null;			
		}				
		
		return attribute;
	}
	
	/**
	 * Build a list of Unique Attribute Names. This method works the same way as {@link #getUniqueAttributes(Map)},
	 * with the only difference that instead of taking the attribute values from the input user attributeMap, it
	 * simply saves the name (key) of the attribute in the returned list.
	 * <p>
	 * The results of this method should match the keys of the Uniqueness Attribute List returned by 
	 * {@link #getUniqueAttributes(Map)}
	 * 
	 * @param attributeMap User attribute map
	 * @return A list of Unique Attribute Names.
	 */
	public List<String> getUniqueAttributeNames(Map<String,Object> attributeMap) {

		List<String> attrNames = new ArrayList<String>();		
		for (String attrSource : uniqueAttrSources) {
			if ( attributeMap.containsKey(attrSource) ) {
				attrNames.add(attrSource);
			}
			// if an attribute is missing from the map we simply ignore it
		}	
		
		return attrNames;
	}
	
	/* DISPLAY AND DEBUG */
	
	@Override
	public String toString() {
		return uniqueAttrSourceList;
	}
	
}
