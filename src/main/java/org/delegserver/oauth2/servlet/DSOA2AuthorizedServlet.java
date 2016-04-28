package org.delegserver.oauth2.servlet;

import org.delegserver.oauth2.DSOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServlet;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;

/**
 * Custom Authorized Servlet implementation (/authorized). 
 * 
 * @author "Tamás Balogh"
 *
 */
public class DSOA2AuthorizedServlet extends OA2AuthorizedServlet {

	/**
	 *  Create a custom Service Transaction {@link DSOA2ServiceTransaction} from a grant.
	 * 
	 *  @param grant The Authorization Grant (code) 
	 */
	@Override
	protected OA2ServiceTransaction createNewTransaction(AuthorizationGrant grant) {
		return new DSOA2ServiceTransaction(grant);
	}
	
}
