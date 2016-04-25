package org.delegserver.oauth2.generator;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.delegserver.oauth2.util.HashingUtils;
import org.delegserver.storage.TraceRecord;

public class UniqueAttrGenerator {

	public static String ATTRIBUTE_SEPARATOR = ",";
	
	protected String[] uniqueAttrSources = null;
	
	public UniqueAttrGenerator(String[] attrSources) {
		this.uniqueAttrSources = attrSources;
	}
	
	/* CHECKER METHODS */
	
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

		// hash and salt attribute list with the same salt used in the trace records
		
		byte[] salt = Base64.decodeBase64( traceRecord.getAttrSalt() );
		
		System.out.println( "Salt (RAW) Extracted for Attribute List Hash : '" + traceRecord.getAttrSalt()  + "'");
		System.out.println( "Salt Extracted for Attribute List Hash : '" + salt + "'");
		
		String attrHash = HashingUtils.getInstance().saltedHashToBase64( attrList , salt );

		System.out.println( "Attribute Hash Computed : '" + attrHash + "'");		
		
		// now for the moment of truth. compare the attribute hash we build with the one previously stored
		
		if ( attrHash.equals( traceRecord.getAttrHash() ) ) {
			
			System.out.println( "Attribute Hash Computed matches Stored Attribute Hash");	
			
			// attribute hash is matching!
			return true;
		} else {
			// attribute hash is not matching! this effectively means that (at least) one of the stored attribute 
			// has a different value than it had before!

			System.out.println( "Attribute Hash Computed DOESNT matches Stored Attribute Hash");	
			
			return false;
		}
	}
	
	/* BUILDER METHODS */
	
	public String getUniqueAttributes(Map<String,String> attributeMap) {
		
		String attrList = null;		
		
		for (String attrSource : uniqueAttrSources) {
			if ( attributeMap.containsKey(attrSource) ) {
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
