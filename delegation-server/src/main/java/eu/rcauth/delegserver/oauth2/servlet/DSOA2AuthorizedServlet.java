package eu.rcauth.delegserver.oauth2.servlet;


import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServlet;

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
