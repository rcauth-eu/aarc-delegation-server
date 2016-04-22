package org.delegserver.oauth2.servlet;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.digest.DigestUtils;
import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.util.DNUtil;
import org.delegserver.storage.TraceRecord;
import org.delegserver.storage.TraceRecordStore;
import org.delegserver.storage.UserAttributeTrace;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
import edu.uiuc.ncsa.security.servlet.PresentableState;

public class DSOA2AuthorizationServerOrig extends OA2AuthorizationServer {

	@Override
	protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
		super.doIt(request, response);
	}
	
	
	@Override
	public void prepare(PresentableState state) throws Throwable {
		super.prepare(state);
		
        if (state.getState() == AUTHORIZATION_ACTION_OK) {
        	AuthorizedState authorizedState = (AuthorizedState) state;
        	OA2ServiceTransaction serviceTransaction = ((OA2ServiceTransaction) authorizedState.getTransaction());
        	
    		TraceRecordStore<TraceRecord> dnRecordStore = ((DSOA2ServiceEnvironment) getServiceEnvironment()).getTraceRecordStore();
    		TraceRecord dnRecord = dnRecordStore.create();
    		
    		/* DN HASHING */
    		
    		String dnHash = DigestUtils.sha256Hex( DNUtil.getUserDN(serviceTransaction) );
    		
    		//MessageDigest md = MessageDigest.getInstance("SHA-256");
    		//md.update( DNUtil.getUserDN(serviceTransaction).getBytes("UTF-8") );
    		//byte[] dnHash = md.digest();
    		
    		System.out.println( "DIGESTING: " + DNUtil.getUserDN(serviceTransaction));
    		//System.out.println("GOT: " + String.format("%x", new BigInteger(1, dnHash)) );
    		System.out.println("GOT: " + dnHash);
    		
    		dnRecord.setCnHash( dnHash );
    		
    		/* ATTRIBUTE HASHING */
        	
        	HttpServletRequest request = authorizedState.getRequest();
        	UserAttributeTrace attrTrace = new  UserAttributeTrace( getHeaderMap(request) );
    		
    		String attributeValueString = null;
			for (String s : attrTrace.getAttributeValues()) {
				if (attributeValueString == null) {
					attributeValueString = s;
				} else {
					attributeValueString += "," + s; 
				}
			}
			
			//byte[] salt = new byte[32];
    		//SecureRandom.getInstance("SHA1PRNG").nextBytes(salt);
    		//String attrSalt =  Hex.encodeHexString(salt);
    		
    		String attrHash = DigestUtils.sha256Hex( attributeValueString + dnHash );
    		
    		System.out.println("DIGESTING: " + attributeValueString + dnHash );
    		System.out.println("GOT: " + attrHash);
    		
    		dnRecord.setAttrHash(attrHash);
    		//dnRecord.setAttrSalt(attrSalt);
    		
    		/* ATTRIBUTE NAMES */
    		
    		String attributeNamesString = null;
			for (String s : attrTrace.getAttributeNames()) {
				if (attributeNamesString == null) {
					attributeNamesString = s;
				} else {
					attributeNamesString += "," + s; 
				}
			}    		
			
			//dnRecord.setAttrNames(attributeNamesString);
    		
    		dnRecordStore.save(dnRecord);
    		
    		
    		//String username = serviceTransaction.getUsername();
    		//String escapedUsername = username.replaceAll("\\/", "\\\\/");
    		//escapedUsername = escapedUsername.replaceAll("=", "\\\\=");
    		//System.out.println("ESCAPED USERNAME: " + escapedUsername);
    		//serviceTransaction.setUsername(escapedUsername);
    		//((DSOA2ServiceEnvironment) getServiceEnvironment()).getTransactionStore().save(serviceTransaction);
        }
	}
	
	private Map<String,String> getHeaderMap(HttpServletRequest request) {
		
		Map<String,String> map = new HashMap<String,String>();
		
        Enumeration e = request.getHeaderNames();
        while (e.hasMoreElements()) {
            String name = e.nextElement().toString();
            map.put(name , request.getHeader(name));
        }
		
		return map;
	}
	
}
