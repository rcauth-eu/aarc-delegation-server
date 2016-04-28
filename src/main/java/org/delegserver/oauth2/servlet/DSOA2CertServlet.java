package org.delegserver.oauth2.servlet;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.DSOA2ServiceTransaction;
import org.delegserver.oauth2.exceptions.AttributeMismatchException;
import org.delegserver.oauth2.exceptions.NoTraceRecordException;
import org.delegserver.oauth2.util.HashingUtils;
import org.delegserver.storage.TraceRecord;
import org.delegserver.storage.TraceRecordIdentifier;
import org.delegserver.storage.TraceRecordStore;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2CertServlet;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;

public class DSOA2CertServlet extends OA2CertServlet {

	protected TraceRecord getTraceRecord(Map<String,String> attributeMap) throws AttributeMismatchException, NoTraceRecordException {
		
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		TraceRecordStore<TraceRecord> traceRecordStore = se.getTraceRecordStore();
		HashingUtils hasher = HashingUtils.getInstance();

		// 1. LOOKUP

		System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++");
		System.out.println("TraceRecord Lookup");
		
		List<Identifier> cnHashAlternatives = new ArrayList<Identifier>();
		
		for ( String cn : se.getDnGenerator().getCommonNames(attributeMap) ) {
			String cnHash = hasher.hashToBase64(cn);	
			cnHashAlternatives.add( new TraceRecordIdentifier(cnHash) );
			System.out.println("Looking for records with PK: " + cnHash);
		}
		
		List<TraceRecord> traceRecords = traceRecordStore.getAll( cnHashAlternatives );
		
		if ( traceRecords == null ) {
			System.out.println("No Record Found!");
			throw new NoTraceRecordException("No Trace Record found based on the user attributes");
		} else {
			System.out.println("Record Found! Record count: " + traceRecords.size());
			
			if ( traceRecords.size() == 0 ) {
				// no records found!
				throw new NoTraceRecordException("No Trace Record found based on the user attributes");
			} else {
				// many results for a single CN, this might mean that we bumped into a collection of DNs only distinguished 
				// by their sequence number
				
				TraceRecord tr = null;
				
				for ( TraceRecord traceRecord : traceRecords ) {
					// need to check for matching attribute set in order to account for things like EPPN reuse.
					if ( se.getUniqueAttrGenerator().matches(attributeMap, traceRecord ) ) {
						
						System.out.println( "Records Match!" );
						
						if ( tr != null ) {
							// found a second match for the attribute set! This should no happen!
							//TODO: This is a corner case somewhat... Should we try to map the user to at least one of the returned 
							//      values? What happens if the user can be perfectly mapped to more then one of these records returned?
							//      Should we just choose a random match? or fail altogether?
							throw new GeneralException("More than one Trace Records from for user !");
						}
						
						// this should be it! 
						tr = traceRecord;
					}
				}
				
				if ( tr == null ) {
					// matching CN but different attribute set! sequence number his ass! 
					throw new AttributeMismatchException("Matching CN but different attribute set! Add a sequence number to the DN!");					
				} else {
					return tr;
				}
			}
		}
	}
	
	protected TraceRecord createTraceRecord(Map<String,String> attributeMap, int sequenceNr) {
		
		System.out.println("-------------- CREATING NEW TRACE RECORD --------------");
		
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		TraceRecordStore<TraceRecord> traceRecordStore = se.getTraceRecordStore();
		HashingUtils hasher = HashingUtils.getInstance();
		
		// first let's populate the database with some records so we can experiment with the lookups
		
		// 2. IF LOOKUP FAILED CREATE DN RECORD 
		
		String cn = se.getDnGenerator().getCommonName(attributeMap); 
		String cnHash = hasher.hashToBase64(cn);
		
		TraceRecord traceRecord = new TraceRecord( new TraceRecordIdentifier(cnHash));
		traceRecord.setCnHash( cnHash );
		
		String attrList = se.getUniqueAttrGenerator().getUniqueAttributes(attributeMap);
		List<String> attrNames = se.getUniqueAttrGenerator().getUniqueAttributeNames(attributeMap);

		if ( attrList != null && ! attrNames.isEmpty()) {
			byte[] attrSalt = hasher.getRandomSalt();
			traceRecord.setAttrHash( hasher.saltedHashToBase64(attrList, attrSalt) );
			traceRecord.setAttrSalt( new String(Base64.encodeBase64(attrSalt)) );
			traceRecord.setAttrNames(attrNames);
		} else {
			throw new GeneralException("Uniqueness Attribute List is empty! Are any of your DN source attributes present?");
		}
		
		traceRecord.setSequenceNr(sequenceNr);
		
		System.out.println("-------------- CREATING NEW TRACE RECORD ENDED --------------");
		System.out.println("-------------- CREATING NEW TRACE RECORD ENDED --------------");
		System.out.println("-------------- CREATING NEW TRACE RECORD ENDED --------------");		
		
		return traceRecord;
	}
	

	@Override
	protected void prepare(ServiceTransaction transaction, HttpServletRequest request, HttpServletResponse response)
			throws Throwable {
		
		super.prepare(transaction, request, response);
		
		// 3. SAVE/UPDATE DN RECORD
		
		DSOA2ServiceTransaction trans = (DSOA2ServiceTransaction) transaction;
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		HashingUtils hasher = HashingUtils.getInstance();
	
		TraceRecord traceRecord = null;
		
		System.out.println(" +++++++++++++ PREPARE +++++++++++++++ ");
		
		try { 
			traceRecord = getTraceRecord( trans.getUserAttributes() );
			System.out.println(" Trace Record found! ");
			
		} catch ( AttributeMismatchException e ) {

			System.out.println(" AttributeMismatchException! Creating new Trace Record with a sequence number");
			
			// new user with matching cn, but different attribute set! 
			// register new trace record with sequence number
			String cn = se.getDnGenerator().getCommonName( trans.getUserAttributes() );
			TraceRecordIdentifier cnId = new TraceRecordIdentifier( hasher.hashToBase64(cn) );
			int nextSequenceNr = se.getTraceRecordStore().getNextSequenceNumber( cnId );
			
			traceRecord = createTraceRecord( trans.getUserAttributes() , nextSequenceNr );
		} catch ( NoTraceRecordException e ) {
			System.out.println(" NoTraceRecordException! Creating new Trace Record without a sequence number");
			// new user! register new trace record
			traceRecord = createTraceRecord( trans.getUserAttributes() , 0 );
		}
		
		System.out.println(" save the trace record ");
		
		se.getTraceRecordStore().save(traceRecord);
		
		trans.setMyproxyUsername( se.getDnGenerator().getUserDNSufix( trans.getUserAttributes() ) );
		trans.setTraceRecord( traceRecord.getCnHash() );

		System.out.println(" save the transaction ");
		
		se.getTransactionStore().save(trans);
		
		System.out.println(" +++++++++++++ PREPARE END +++++++++++++++ ");
		System.out.flush();	
	}
	
	
	@Override
	protected void checkMPConnection(OA2ServiceTransaction st) throws GeneralSecurityException {
		createMPConnection(st.getIdentifier(), st.getMyproxyUsername(), "", st.getLifetime());
	}
	
	/*
	@Override
	protected void doRealCertRequest(ServiceTransaction trans, String statusString) throws Throwable {
		// 4. CREATE MYPROXY CONNECTION BASED ON DN RECORD
	}
	*/
	
}
