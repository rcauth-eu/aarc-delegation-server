package org.delegserver.oauth2.servlet;

import java.nio.charset.Charset;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.DSOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
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
        	DSOA2ServiceTransaction serviceTransaction = ((DSOA2ServiceTransaction) authorizedState.getTransaction());
        	
        	printAllParameters( authorizedState.getRequest() );
        	
        	serviceTransaction.setUserAttributes( getHeaderMap(state.getRequest()) );
        	getTransactionStore().save(serviceTransaction);
        	
        	DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();
        	// TODO: write a more generic attribute mapper 
        	System.out.println("-------------- GENERATED RDNS --------------");
        	
        	String org = se.getDnGenerator().getOrganisation(getHeaderMap(state.getRequest()));
        	System.out.println("/O=" + org);
        	System.out.println("length = " + org.getBytes("UTF-8").length);
        	
        	String cn = se.getDnGenerator().getCommonName(getHeaderMap(state.getRequest()));
        	System.out.println("/CN=" + cn);
        	System.out.println("length = " + cn.getBytes("UTF-8").length);

        	System.out.println("-------------- GENERATED DN --------------");
        	String dn = se.getDnGenerator().getUserDNSufix(getHeaderMap(state.getRequest()));
        	System.out.println("DN : " + dn);
        	System.out.println("-------------- END GENERATED DN 1 --------------");
        	System.out.println("-------------- END GENERATED DN 2 --------------");
        	System.out.println("-------------- END GENERATED DN 3 --------------");
        }
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
