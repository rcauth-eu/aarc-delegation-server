package org.delegserver.oauth2.servlet;


import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.DSOA2ServiceTransaction;
import org.delegserver.oauth2.exceptions.AttributeMismatchException;
import org.delegserver.oauth2.exceptions.IncompleteAttributeSetException;
import org.delegserver.oauth2.exceptions.NoTraceRecordException;
import org.delegserver.oauth2.util.HashingUtils;
import org.delegserver.storage.RDNElement;
import org.delegserver.storage.RDNElementPart;
import org.delegserver.storage.TraceRecord;
import org.delegserver.storage.TraceRecordIdentifier;
import org.delegserver.storage.TraceRecordStore;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2CertServlet;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;

//import static edu.uiuc.ncsa.security.oauth_2_0.server.OA2Claims.EMAIL;

/**
 * Custom Cert Servlet implementation (/getcert) which supports the use of
 * {@link TraceRecord} for user tracking and DN Generation based on user attributes.
 * <p>
 * For more details on DNs  are constructed consult the RCauth Policy Document
 * ( https://rcauth.eu/policy ) section 3.1.2.
 * 
 * @author "Tamás Balogh"
 * @see <a href="https://rcauth.eu/policy">https://rcauth.eu/policy</a>
 *
 */
public class DSOA2CertServlet extends OA2CertServlet {

	/* OVERRIDEN METHODS */
	
	/**
	 * Extends the functionality of the basic method by adding support for working with
	 * {@link TraceRecord}s. It either retrieves an already existing, or creates a new trace record 
	 * based on the current transaction.
	 * <p>
	 * Moreover, this method also generates the final user DN which will be passed along to the
	 * MyProxy connection. Both trace record and transaction should get updates by this method.
	 * 
	 * @param transaction The current Service Transaction
	 * @param statusString Status string
	 */
	@Override
	protected void doRealCertRequest(ServiceTransaction transaction, String statusString) throws Throwable {		
	
		DSOA2ServiceTransaction trans = (DSOA2ServiceTransaction) transaction;
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		HashingUtils hasher = HashingUtils.getInstance();
	
		/* DEBUG AND TRACE LOGGING */
		// initialize the session specific trace logger with the transaction identifier.
		se.getTraceLogger().initSessionLogger( trans.getIdentifierString() );
		se.getTraceLogger().marked("NEW GETCERT REQUEST [transaction: " + trans.getIdentifierString()  +"]");
    	
		// 1. GET TRACE RECORD FOR THIS TRANSACTION
		traceDebug("6.a.1  Get trace record for current transaction");
		
		TraceRecord traceRecord = null;
		
		try {
			
			// 2. TRY TO RETRIVE ALREADY EXISTING TRACE RECORD BASED ON CURRENT TRANSACTION
			traceDebug("6.a.2  Look for an already existing trace record");
			traceRecord = getTraceRecord( trans.getUserAttributes() );
			traceDebug("6.a.2  Trace Record FOUND!");
			
		} catch ( AttributeMismatchException e ) {

			// 2.a CREATE NEW TRACE RECORD WITH SEQUENCE NUMBER
			traceDebug("6.a.2 AttributeMismatchException! Trace record found, but attributes hashed did not match. Creating new Trace Record with a sequence number");
			
			// register new trace record with sequence number 0 for a start
			traceRecord = createTraceRecord( trans.getUserAttributes() , 0 );
			
			// new user with matching CN, but different attribute set! 
		    // get the next sequence  number for the generated CN
			TraceRecordIdentifier cnId = (TraceRecordIdentifier) traceRecord.getIdentifier();
			int nextSequenceNr = se.getTraceRecordStore().getNextSequenceNumber( cnId );
			
			// set the next assigned sequence number to the current record
			traceRecord.setSequenceNr(nextSequenceNr);
			
		} catch ( NoTraceRecordException e ) {
			
			// 2.b CREATE NEW TRACE RECORD WITH SEQUNCE NUMBER 0
			traceDebug("6.a.2 NoTraceRecordException! Trace record not found. Creating new Trace Record without a sequence number");
			
			// new user! register new trace record
			traceRecord = createTraceRecord( trans.getUserAttributes() , 0 );
		}
		
		// by now we should already have a trace record. if not we shouldn't continue!  
		if ( traceRecord == null ) {
			throw new GeneralException("Could not create/retrieve trace record for the current transaction!");
		}

		// 3. SAVE TRACE RECORD
		traceDebug("6.a.3 Saving trace record");		
		se.getTraceRecordStore().save(traceRecord);
		
		// 4. GENERATE USER DN FOR TRANSACTION AND SAVE TRANSACTION
		traceDebug("6.a.4 Generating user DN for transaction...");		
		//the DN sufix should be taken from the trace record retrieved/created above!!!
		//if you recreate the CN at this point using DnGenerator you might end up
		//creating a new CN for an already existing user in the system.
		RDNElement cnRDN = traceRecord.getCommonName();
		int cnRDNseqNr = traceRecord.getSequenceNr();
		//the O can be recreated from scratch because we don't track modifications
		RDNElement orgRDN = se.getDnGenerator().getOrganisation( trans.getUserAttributes() );
		traceRecord.setOrganization(orgRDN);
		
		//append the sequence number where applicable 
		if ( cnRDNseqNr > 0 ) {
			trans.setMyproxyUsername( se.getDnGenerator().formatDNSufix( orgRDN.getElement() , cnRDN.getElement(), cnRDNseqNr ) );
		} else {
			trans.setMyproxyUsername( se.getDnGenerator().formatDNSufix( orgRDN.getElement() , cnRDN.getElement() ) );	
		}
		
		//log the final trace record elements and their origin
		logTraceRecord(traceRecord);
		traceDebug("6.a.4 The generated user DN is: " + trans.getMyproxyUsername());		

		//complete the USERNAME parameter with extensions 
		String additionalInfo = se.getCertExtGenerator().getCertificateExtensions( trans.getUserAttributes() );

		if ( additionalInfo != null ) { 
			trans.setMyproxyUsername( trans.getMyproxyUsername() + " " + additionalInfo );
			traceDebug("6.a.5 Full MyProxy username: " + trans.getMyproxyUsername());
		} else {
			traceDebug("6.a.5 No extensions appended into the certificate request. Requesting cert without it");
		}

		traceInfo("Full MyProxy username: " + trans.getMyproxyUsername());		
		
		trans.setTraceRecord( traceRecord.getCnHash() );
		
		se.getTransactionStore().save(trans);
		
		// destroy the session specific trace logger
		se.getTraceLogger().destroySessionLogger();
		
		// 5. PROCEED WITH MYPROXY CALL
        checkMPConnection(trans);
        doCertRequest(trans, statusString);
	}
	
	
	@Override
	protected void checkMPConnection(OA2ServiceTransaction st) throws GeneralSecurityException {
		// 6. CREATE MYPROXY CONNECTION BASED ON DN RECORD
		info("6.a.5 Creating MyProxy connection");		
		createMPConnection(st.getIdentifier(), st.getMyproxyUsername(), "", st.getLifetime());
	}
	
	/* NEW HELPER METHODS FOR TRACE RECORD MANIPULATION */
	

	
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
	protected TraceRecord getTraceRecord(Map<String,Object> attributeMap) throws AttributeMismatchException, NoTraceRecordException {
		
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		TraceRecordStore<TraceRecord> traceRecordStore = se.getTraceRecordStore();
		HashingUtils hasher = HashingUtils.getInstance();

		// 1. GENERATE EVERY POSSIBLE CN HASH
		
		// keep a reverse mapping between the original CNs (inside a RDNElement) and their hashes 
		Map<TraceRecordIdentifier, RDNElement> cnHashAlternatives = new HashMap<TraceRecordIdentifier, RDNElement>();
		
		for ( RDNElement cn : se.getDnGenerator().getCommonNames(attributeMap) ) {
			// hash possible CNs and then to the lookup list.
			String cnHash = hasher.hashToBase64(cn.getElement());	
			traceDebug("Looking for trace record with CN Hash:" + cnHash + " ( " + cn.getElement() + " )");
			cnHashAlternatives.put(new TraceRecordIdentifier(cnHash) ,cn );
		}
		
		// 2. LOOKUP TRACE RECORDS WITH THE ABOVE GENERATES CN HASHES
		traceDebug("Executing lookup for trace records...");
		// execute the lookup based on the set of CN hashes (reverse map keys)
		List<TraceRecord> traceRecords = traceRecordStore.getAll( new ArrayList<Identifier>( cnHashAlternatives.keySet() ) );
		
		if ( traceRecords == null || traceRecords.size() == 0 ) {
			// 2.a NO TRACE RECORDS
			traceDebug("No Trace Records Found with any of the provided CN hashes!");
			throw new NoTraceRecordException("No Trace Record found based on the user attributes");
		} else {
			// 2.b TRACE RECORDS FOUND		
			traceDebug("Trace Records Found! Record count: " + traceRecords.size());
			
			// many results for a single CN, this might mean that we bumped into a collection of DNs only distinguished 
			// by their sequence number
			
			TraceRecord matchingTraceRecord = null;
			for ( int i=0; i<traceRecords.size(); i++ ) {
				
				TraceRecord traceRecord = traceRecords.get(i);
				
				// need to check for matching attribute set in order to account for things like EPPN reuse.
				traceDebug("Matching trace record " + traceRecord.getCnHash() + " " + traceRecord.getSequenceNr());
				
				try {
					
					if ( se.getUniqueAttrGenerator().matches(attributeMap, traceRecord ) ) {
						
						traceDebug("Trace Record matches attribute set!");	
						
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
						traceDebug("Trace Record does NOT match attribute set! Mismatch on hashed attributes!");			
						if (i == 0) { 
							// log as warn if the last seen user attribute changes
							traceWarn("Change in last seen user attribute! Mismatch on hashed content!");
						}
					}
				
				} catch (IncompleteAttributeSetException e) {
					traceDebug("Trace Record does NOT match attribute set! Different attribute set!");				
					if (i == 0) { 
						// log as warn if the last seen user attribute changes
						traceWarn(e.getMessage());
					}
				}
			}
			
			if ( matchingTraceRecord == null ) {
				// matching CN but different attribute set! sequence number his ass!
				traceDebug("No Trace Record matched the attribute set...");
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
	protected TraceRecord createTraceRecord(Map<String,Object> attributeMap, int sequenceNr) {
		
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		HashingUtils hasher = HashingUtils.getInstance();
		
		// 1. Generate CN for Trace Record
		RDNElement cn = se.getDnGenerator().getCommonName(attributeMap); 
		String cnHash = hasher.hashToBase64(cn.getElement());
		
		traceDebug("Generating Trace Record with CN hash: " + cnHash + " ( " + cn.getElement() + " ) and sequence nr: " + sequenceNr );
		TraceRecord traceRecord = new TraceRecord( new TraceRecordIdentifier(cnHash) );
		traceRecord.setCommonName(cn);
		traceRecord.setCnHash( cnHash );
		traceRecord.setSequenceNr(sequenceNr);

		// 2. Generate Unique Attribute List for Trace Record
		traceDebug("Generated Unique attribute list ... ");
		String attrList = se.getUniqueAttrGenerator().getUniqueAttributes(attributeMap);
		List<String> attrNames = se.getUniqueAttrGenerator().getUniqueAttributeNames(attributeMap);
		traceDebug("Generated Unique attribute source names : '" + attrNames + "'");
		traceDebug("Generated Unique attribute list for trace record : '" + attrList + "'");

		if ( attrList != null && ! attrNames.isEmpty()) {
			// 3. Salt and hash Unique Attribute List
			traceDebug("Generating random salt ...");
			byte[] attrSalt = hasher.getRandomSalt();
			traceRecord.setAttrHash( hasher.saltedHashToBase64(attrList, attrSalt) );
			traceRecord.setAttrSalt( new String(Base64.encodeBase64(attrSalt)) );
			traceRecord.setAttrNames(attrNames);
			traceDebug("Generated hashed attribute list : '" + traceRecord.getAttrHash() + "'");
		} else {
			error("Uniqueness Attribute List is empty!");
			throw new GeneralException("Uniqueness Attribute List is empty! Are any of your DN source attributes present?");
		}

		return traceRecord;
	}	
	
	/* DEBUG AND DISPLAY */
	
	public void logTraceRecord(TraceRecord traceRecord) {
		logTraceRecordElement( traceRecord.getOrganization() );
		logTraceRecordElement( traceRecord.getCommonName() );
	}
	
	public void logTraceRecordElement(RDNElement element) {
		for ( RDNElementPart rdnPart : element.getElementParts() ) {
		
			StringBuilder orgTrace = new StringBuilder();
			
			orgTrace.append("RDN : '" + rdnPart.getElement() + "' ");
			orgTrace.append("(" + rdnPart.getElementSource() + " = ");
			orgTrace.append("'" + rdnPart.getElementOrig() + "')");

			
			traceInfo(orgTrace.toString());
		}
	}
	
	public void traceInfo(String x) {
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		se.getTraceLogger().info(x);
	}
	
	public void traceDebug(String x) {
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		se.getTraceLogger().debug(x);
	}
	
	public void traceError(String x) {
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		se.getTraceLogger().error(x);
	}
	
	public void traceWarn(String x) {
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		se.getTraceLogger().warn(x);
	}	
}
