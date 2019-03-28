package org.delegserver.oauth2.servlet;

import org.delegserver.oauth2.DSOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServletUtil;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;

/**
 * Custom Authorized Servlet implementation (/authorized).
 *
 * @author "Tamás Balogh"
 * @author "Mischa Sall&eacute;"
 *
 */
public class DSOA2AuthorizedServletUtil extends OA2AuthorizedServletUtil {

    public DSOA2AuthorizedServletUtil(MyProxyDelegationServlet servlet) {
        super(servlet);
    }

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
