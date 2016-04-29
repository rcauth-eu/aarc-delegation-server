package org.delegserver.oauth2.generator;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.delegserver.oauth2.util.HashingUtils;
import org.delegserver.storage.TraceRecord;

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
	
	/* CONSTRUCTOR */
	
	/**
	 * Create A Unique Attribute Generator based on a set of attribute sources. 
	 * 
	 * @param attrSources Attribute Sources 
	 */
	public UniqueAttrGenerator(String[] attrSources) {
		this.uniqueAttrSources = attrSources;
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
	 */
	public boolean matches(Map<String,String> attributeMap, TraceRecord traceRecord) {
		
		System.out.println( "========== START MATCHING ===========" );
		
		// build attribute list using the attribute names in the traceRecords previously stored
		
		String attrList = null;		
		for (String attrSource : traceRecord.getAttrNames()) {
			if ( attributeMap.containsKey(attrSource) ) {
				if ( attrList == null ) {
					attrList = attributeMap.get(attrSource);
				} else {
					attrList += ATTRIBUTE_SEPARATOR + attributeMap.get(attrSource);			
				}
			} else {

				System.out.println( "Attribute " + attrSource + " not found!" );
				System.out.println( "Mismatch between stored attributes and present attributes" );
				
				// mismatch between the attributes saved and attributes present in the attributeMap 
				// (when an attribute which was previously used to construct the hash is missing,
				//  we can be sure that the attribute list hashes will not be the same)
				return false;
			}
		}

		System.out.println( "Attribute List Computed : '" + attrList + "'");

		// salt and hash attribute list with the same salt used in the trace records
		
		byte[] salt = Base64.decodeBase64( traceRecord.getAttrSalt() );
		
		System.out.println( "Salt (RAW) Extracted for Attribute List Hash : '" + traceRecord.getAttrSalt()  + "'");
		System.out.println( "Salt Extracted for Attribute List Hash : '" + salt + "'");
		
		String attrHash = HashingUtils.getInstance().saltedHashToBase64( attrList , salt );

		System.out.println( "Attribute Hash Computed : '" + attrHash + "'");		
		
		// now for the moment of truth. compare the attribute hash we built with the one previously stored
		
		if ( attrHash.equals( traceRecord.getAttrHash() ) ) {
			
			System.out.println( "Attribute Hash Computed matches Stored Attribute Hash");	
			
			// attribute hash is matching!
			return true;
		} else {
			// attribute hash is not matching! this effectively means that (at least) one of the stored attribute 
			// has a different value than it had before! It is impossible to say which tho.

			System.out.println( "Attribute Hash Computed DOESNT matches Stored Attribute Hash");	
			
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
	public String getUniqueAttributes(Map<String,String> attributeMap) {
		
		String attrList = null;		
		
		// iterate over the source attributes 
		for (String attrSource : uniqueAttrSources) {
			if ( attributeMap.containsKey(attrSource) ) {
				// if an attribute is present in the user map, add it to the list
				if ( attrList == null ) {
					attrList = attributeMap.get(attrSource);
				} else {
					attrList += ATTRIBUTE_SEPARATOR + attributeMap.get(attrSource);			
				}
			}
			// if an attribute is missing from the map we simply ignore it
		}
		
		return attrList;
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
	public List<String> getUniqueAttributeNames(Map<String,String> attributeMap) {

		List<String> attrNames = new ArrayList<String>();		
		for (String attrSource : uniqueAttrSources) {
			if ( attributeMap.containsKey(attrSource) ) {
				attrNames.add(attrSource);
			}
			// if an attribute is missing from the map we simply ignore it
		}	
		
		return attrNames;
	}
	
}
