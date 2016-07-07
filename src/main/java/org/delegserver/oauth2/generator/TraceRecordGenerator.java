package org.delegserver.oauth2.generator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.delegserver.oauth2.exceptions.AttributeMismatchException;
import org.delegserver.oauth2.exceptions.IncompleteAttributeSetException;
import org.delegserver.oauth2.exceptions.NoTraceRecordException;
import org.delegserver.oauth2.util.HashingUtils;
import org.delegserver.storage.RDNElement;
import org.delegserver.storage.TraceRecord;
import org.delegserver.storage.TraceRecordIdentifier;
import org.delegserver.storage.TraceRecordStore;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * Generates {@link TraceRecord}s based on the provided user attributes.
 * 
 * @author "Tamás Balogh"
 *
 */
public class TraceRecordGenerator {

	protected TraceRecordStore<TraceRecord> traceRecordStore = null; 
	protected DNGenerator dnGenerator = null;
	protected UniqueAttrGenerator uniqueAttrGenerator = null;
	
	protected Logable logger = null;
	
	public TraceRecordGenerator(TraceRecordStore<TraceRecord> trStore, DNGenerator dnGen, UniqueAttrGenerator uniqueAttrGen, Logable logger) {
	
		this.traceRecordStore = trStore;
		this.dnGenerator = dnGen;
		this.uniqueAttrGenerator = uniqueAttrGen;
		this.logger = logger;
		
	}
	
	/* METHODS FOR TRACE RECORD GENERATION */

	/**
	 * It either retrieves an already existing, or creates a new {@link TraceRecord}
	 * based on the passed user attributes.
	 * 
	 * @param attributeMap The user attributes 
	 * @returns The TraceRecord generated
	 */
	public TraceRecord generate(Map<String,Object> attributeMap) {
		
		TraceRecord traceRecord = null;
		
		try {
			
			// 2. TRY TO RETRIVE ALREADY EXISTING TRACE RECORD BASED ON CURRENT TRANSACTION
			logger.debug("6.a.2  Look for an already existing trace record");
			traceRecord = getTraceRecord( attributeMap );
			logger.debug("6.a.2  Trace Record FOUND!");
			
		} catch ( AttributeMismatchException e ) {

			// 2.a CREATE NEW TRACE RECORD WITH SEQUENCE NUMBER
			logger.debug("6.a.2 AttributeMismatchException! Trace record found, but attributes hashed did not match. Creating new Trace Record with a sequence number");
			
			// register new trace record with sequence number 0 for a start
			traceRecord = createTraceRecord( attributeMap , 0 );
			
			// new user with matching CN, but different attribute set! 
		    // get the next sequence  number for the generated CN
			TraceRecordIdentifier cnId = (TraceRecordIdentifier) traceRecord.getIdentifier();
			int nextSequenceNr = traceRecordStore.getNextSequenceNumber( cnId );
			
			// set the next assigned sequence number to the current record
			traceRecord.setSequenceNr(nextSequenceNr);
			
		} catch ( NoTraceRecordException e ) {
			
			// 2.b CREATE NEW TRACE RECORD WITH SEQUNCE NUMBER 0
			logger.debug("6.a.2 NoTraceRecordException! Trace record not found. Creating new Trace Record without a sequence number");
			
			// new user! register new trace record
			traceRecord = createTraceRecord( attributeMap , 0 );
		}
		
		//the O can be recreated from scratch because we don't track modifications
		RDNElement orgRDN = dnGenerator.getOrganisation( attributeMap );
		traceRecord.setOrganization(orgRDN);
		
		return traceRecord;
	}
	
	/**
	 * Retrieve and match a {@link TraceRecord} based on the set of attributes in the attributeMap. This method will
	 * derive a set of possible CNs from the attributeMap. A set of {@link TraceRecord}s (TR) is then queried based on the
	 * previously generated CN set. Further matching is then applied to the set of trace records to find 
	 * a match. 
	 * <p>
	 * In case (TR) is empty, {@link NoTraceRecordException} is throw. In case (TR) is not empty, but non of the trace 
	 * records match the attributes presented from attributeMap, {@link AttributeMismatchException} is thrown. In case 
	 * (TR) is not empty, and there is only one matching trace record, return it. In case (TR) is not empty, but there
	 * are more then one matching trace records, fail with a {@link GeneralException}
	 * 
	 * @param attributeMap User attribute map
	 * @return The trace record matching the attributeMap
	 * @throws AttributeMismatchException When there are trace records but their attributes do not match
	 * @throws NoTraceRecordException When there are no trace records 
	 */
	public TraceRecord getTraceRecord(Map<String,Object> attributeMap) throws AttributeMismatchException, NoTraceRecordException {
		
		HashingUtils hasher = HashingUtils.getInstance();

		// 1. GENERATE EVERY POSSIBLE CN HASH
		
		// keep a reverse mapping between the original CNs (inside a RDNElement) and their hashes 
		Map<TraceRecordIdentifier, RDNElement> cnHashAlternatives = new HashMap<TraceRecordIdentifier, RDNElement>();
		
		for ( RDNElement cn : dnGenerator.getCommonNames(attributeMap) ) {
			// hash possible CNs and then to the lookup list.
			String cnHash = hasher.hashToBase64(cn.getElement());	
			logger.debug("Looking for trace record with CN Hash:" + cnHash + " ( " + cn.getElement() + " )");
			cnHashAlternatives.put(new TraceRecordIdentifier(cnHash) ,cn );
		}
		
		// 2. LOOKUP TRACE RECORDS WITH THE ABOVE GENERATES CN HASHES
		logger.debug("Executing lookup for trace records...");
		// execute the lookup based on the set of CN hashes (reverse map keys)
		List<TraceRecord> traceRecords = traceRecordStore.getAll( new ArrayList<Identifier>( cnHashAlternatives.keySet() ) );
		
		if ( traceRecords == null || traceRecords.size() == 0 ) {
			// 2.a NO TRACE RECORDS
			logger.debug("No Trace Records Found with any of the provided CN hashes!");
			throw new NoTraceRecordException("No Trace Record found based on the user attributes");
		} else {
			// 2.b TRACE RECORDS FOUND		
			logger.debug("Trace Records Found! Record count: " + traceRecords.size());
			
			// many results for a single CN, this might mean that we bumped into a collection of DNs only distinguished 
			// by their sequence number
			
			TraceRecord matchingTraceRecord = null;
			for ( int i=0; i<traceRecords.size(); i++ ) {
				
				TraceRecord traceRecord = traceRecords.get(i);
				
				// need to check for matching attribute set in order to account for things like EPPN reuse.
				logger.debug("Matching trace record " + traceRecord.getCnHash() + " " + traceRecord.getSequenceNr());
				
				try {
					
					if ( uniqueAttrGenerator.matches(attributeMap, traceRecord ) ) {
						
						logger.debug("Trace Record matches attribute set!");	
						
						/*
						if ( matchingTraceRecord != null ) {
							// found a second match for the attribute set! This should not happen!
							//TODO: This is a corner case somewhat... Should we try to map the user to at least one of the returned 
							//      values? What happens if the user can be perfectly mapped to more then one of these records returned?
							//      Should we just choose a random match? or fail altogether?
							throw new GeneralException("More than one Trace Record matched the user attributes!");
						}
						*/
						
						// this should be it! 
						matchingTraceRecord = traceRecord;
						
						// find original CN that produced that match
						RDNElement originalCN = cnHashAlternatives.get( new TraceRecordIdentifier(matchingTraceRecord.getCnHash()));
						if ( originalCN == null ) {
							// this means something is wrong in the original reverse map. We need the original CN here
							// otherwise we might end up constructing it from the wrong source attributes.
							throw new GeneralException("Matching transaction found, but could not get original CN!");
						}
						matchingTraceRecord.setCommonName( originalCN );
						
						// Instead of looking for other matches, just simple take the fist one. The trace records 
						// returned by the DB are ordered by their last_seen date, which makes the trace record matching
						// deterministic in case of multiple matches.
						break;
						
					} else {
						logger.debug("Trace Record does NOT match attribute set! Mismatch on hashed attributes!");			
						if (i == 0) { 
							// log as warn if the last seen user attribute changes
							logger.warn("Change in last seen user attribute! Mismatch on hashed content!");
						}
					}
				
				} catch (IncompleteAttributeSetException e) {
					logger.debug("Trace Record does NOT match attribute set! Different attribute set!");				
					if (i == 0) { 
						// log as warn if the last seen user attribute changes
						logger.warn(e.getMessage());
					}
				}
			}
			
			if ( matchingTraceRecord == null ) {
				// matching CN but different attribute set! sequence number his ass!
				logger.debug("No Trace Record matched the attribute set...");
				throw new AttributeMismatchException("Matching CN but different attribute set! Add a sequence number to the DN!");					
			} else {
				return matchingTraceRecord;
			}

		}
	}
	
	/**
	 * Create a new {@link TraceRecord} based on the user attributes in the attributeMap and the 
	 * appended sequence number. The sequence number of a {@link TraceRecord} should usually be left 0.
	 * This method takes care of creating all the right attribute hashes.
	 * 
	 * @param attributeMap User attribute map
	 * @param sequenceNr Sequence number of the {@link TraceRecord} to be created. Usually it's 0.
	 * @return The {@link TraceRecord} created from the attributeMap and sequenceNr
	 */
	public TraceRecord createTraceRecord(Map<String,Object> attributeMap, int sequenceNr) {
		
		HashingUtils hasher = HashingUtils.getInstance();
		
		// 1. Generate CN for Trace Record
		RDNElement cn = dnGenerator.getCommonName(attributeMap); 
		String cnHash = hasher.hashToBase64(cn.getElement());
		
		logger.debug("Generating Trace Record with CN hash: " + cnHash + " ( " + cn.getElement() + " ) and sequence nr: " + sequenceNr );
		TraceRecord traceRecord = new TraceRecord( new TraceRecordIdentifier(cnHash) );
		traceRecord.setCommonName(cn);
		traceRecord.setCnHash( cnHash );
		traceRecord.setSequenceNr(sequenceNr);

		// 2. Generate Unique Attribute List for Trace Record
		logger.debug("Generated Unique attribute list ... ");
		String attrList = uniqueAttrGenerator.getUniqueAttributes(attributeMap);
		List<String> attrNames = uniqueAttrGenerator.getUniqueAttributeNames(attributeMap);
		logger.debug("Generated Unique attribute source names : '" + attrNames + "'");
		logger.debug("Generated Unique attribute list for trace record : '" + attrList + "'");

		if ( attrList != null && ! attrNames.isEmpty()) {
			// 3. Salt and hash Unique Attribute List
			logger.debug("Generating random salt ...");
			byte[] attrSalt = hasher.getRandomSalt();
			traceRecord.setAttrHash( hasher.saltedHashToBase64(attrList, attrSalt) );
			traceRecord.setAttrSalt( new String(Base64.encodeBase64(attrSalt)) );
			traceRecord.setAttrNames(attrNames);
			logger.debug("Generated hashed attribute list : '" + traceRecord.getAttrHash() + "'");
		} else {
			logger.error("Uniqueness Attribute List is empty!");
			throw new GeneralException("Uniqueness Attribute List is empty! Are any of your DN source attributes present?");
		}

		return traceRecord;
	}		
	
	
}
