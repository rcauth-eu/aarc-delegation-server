package org.delegserver.oauth2.servlet;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.util.HashingUtils;
import org.delegserver.storage.TraceRecord;
import org.delegserver.storage.TraceRecordStore;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2CertServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;

public class DSOA2CertServlet extends OA2CertServlet {

	protected TraceRecord getTraceRecord(Map<String,String> attributeMap) {
		
		DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
		TraceRecordStore<TraceRecord> traceRecordStore = ((DSOA2ServiceEnvironment) getServiceEnvironment()).getDNRecordStore();
		HashingUtils hasher = HashingUtils.getInstance();
		// 1. LOOKUP
		
		// first let's populate the database with some records so we can experiment with the lookups
		
		// 2. IF LOOKUP FAILED CREATE DN RECORD 
		
		TraceRecord traceRecord = traceRecordStore.create();
		
		String cn = se.getDnGenerator().getCommonName(attributeMap); 
		traceRecord.setCnHash( hasher.hashToBase64(cn) );
		
		String attrList = null;
		List<String> attrNames = new ArrayList<String>();		
		for (String attrSource : se.getUniqueAttrSources()) {
			if ( attributeMap.containsKey(attrSource) ) {
				if ( attrList == null && attrNames == null ) {
					attrList = attributeMap.get(attrSource);
				} else {
					attrList += "," + attributeMap.get(attrSource);			
				}
				attrNames.add(attrSource);
			}
			// if an attribute is missing from the map we simply ignore it
		}
		if ( attrList != null ) {
			byte[] attrSalt = hasher.getRandomSalt();
			traceRecord.setAttrHash( hasher.saltedHashToBase64(attrList, attrSalt) );
			traceRecord.setAttrSalt( new String(Base64.encodeBase64(attrSalt)) );
			traceRecord.setAttrNames(attrNames);
		} else {
			throw new GeneralException("Uniqueness Attribute List is empty! Are any of your DN source attributes present?");
		}
		
		traceRecordStore.save(traceRecord);
		
		return null;
	}
	
	@Override
	protected void prepare(ServiceTransaction transaction, HttpServletRequest request, HttpServletResponse response)
			throws Throwable {
		super.prepare(transaction, request, response);
		
		TraceRecord trace = getTraceRecord( getHeaderMap(request) );
		
	}
	
	@Override
	protected void doRealCertRequest(ServiceTransaction trans, String statusString) throws Throwable {
		//super.doRealCertRequest(trans, statusString);
		
		// 3. SAVE/UPDATE DN RECORD
		
		// 4. CREATE MYPROXY CONNECTION BASED ON DN RECORD
	}
	
	private Map<String,String> getHeaderMap(HttpServletRequest request) {
		
		Map<String,String> map = new HashMap<String,String>();
		
		// IMPORTANT !!! Map the header parameters wih the right encoding 
		
		Charset isoCharset = Charset.forName("ISO-8859-1");
		Charset utf8Charset = Charset.forName("UTF-8");
		
        Enumeration e = request.getHeaderNames();
        while (e.hasMoreElements()) {
            String name = e.nextElement().toString();
            
            byte[] v = request.getHeader(name).getBytes(isoCharset);
            String value = new String(v,utf8Charset);
            
            map.put(name , value );
        }
		
		return map;
	}	
}
