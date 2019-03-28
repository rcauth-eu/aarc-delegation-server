package org.delegserver.oauth2.servlet;

import org.delegserver.oauth2.DSOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServlet;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;

/**
 * Custom Authorized Servlet implementation (/authorized). 
 *
 * @author "Tamás Balogh"
 * @author "Mischa Sall&eacute;"
 *
 */
public class DSOA2AuthorizedServlet extends OA2AuthorizedServlet {

    @Override
    public DSOA2AuthorizedServletUtil getInitUtil(){
        if (initUtil == null) {
            initUtil = new DSOA2AuthorizedServletUtil(this);
        }
        return (DSOA2AuthorizedServletUtil)initUtil;
    }

}
