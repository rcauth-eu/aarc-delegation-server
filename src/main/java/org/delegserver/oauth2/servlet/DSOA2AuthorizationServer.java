package org.delegserver.oauth2.servlet;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.digest.DigestUtils;
import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.util.DNUtil;
import org.delegserver.storage.DNRecord;
import org.delegserver.storage.DNRecordStore;
import org.delegserver.storage.UserAttributeTrace;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
import edu.uiuc.ncsa.security.delegation.services.Request;
import edu.uiuc.ncsa.security.servlet.PresentableState;

public class DSOA2AuthorizationServer extends OA2AuthorizationServer {

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
        	
        	printAllParameters( authorizedState.getRequest() );
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
	
	
	@Override
	protected void printAllParameters(HttpServletRequest request) {
		super.printAllParameters(request);
		
		System.out.println("Attributes:");
        Enumeration e = request.getAttributeNames();
        if (!e.hasMoreElements()) {
            System.out.println(" (none)");
        } else {
            while (e.hasMoreElements()) {
                String name = e.nextElement().toString();
                System.out.println(" " + name);
                System.out.println("   " + request.getAttribute(name));
            }
        }
        
        System.out.println(" " + "AJP_sn");
        System.out.println("   " + request.getAttribute("AJP_sn"));
	}
	
}
