package eu.rcauth.delegserver.oauth2.servlet;

import java.security.GeneralSecurityException;

import eu.rcauth.delegserver.oauth2.DSOA2ServiceEnvironment;
import eu.rcauth.delegserver.oauth2.DSOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2CertServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;

/**
 * Custom Cert Servlet implementation (/getcert) that uses the MyProxy
 * username set by the /authorize call to make the MyProxy connection
 *
 * @author "Tamás Balogh"
 */
public class DSOA2CertServlet extends OA2CertServlet {

    /* OVERRIDDEN METHODS */

    @Override
    protected void doRealCertRequest(ServiceTransaction transaction, String statusString) throws Throwable {

        DSOA2ServiceTransaction trans = (DSOA2ServiceTransaction) transaction;
        DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment) getServiceEnvironment();

        /* DEBUG AND TRACE LOGGING */
        // initialize the session specific trace logger with the transaction identifier.
        se.getTraceLogger().initSessionLogger( trans.getIdentifierString() );
        se.getTraceLogger().marked("NEW GETCERT REQUEST [transaction: " + trans.getIdentifierString()  +"]");

        String username = trans.getMyproxyUsername();
        if ( username == null || username.isEmpty() ) {
            se.getTraceLogger().error("MyProxy USERNAME not set for current transaction! " +
                                      "Make sure that the MyProxy USERNAME is created and" +
                                      "saved in the current transaction before calling /getcert!");
            throw new GeneralException("MyProxy USERNAME not set for current transaction!");
        }

        se.getTraceLogger().debug("Proceeding with MyProxy call with username : " + username);

        // destroy the session specific trace logger
        se.getTraceLogger().destroySessionLogger();

        /* PROCEED WITH MYPROXY CALL */
        checkMPConnection(trans);
        doCertRequest(trans, statusString);
    }


    @Override
    protected void checkMPConnection(OA2ServiceTransaction st) throws GeneralSecurityException {
        // create MyProxy connection based the USERNAME containing the user DN
        info("6.a.5 Creating MyProxy connection");
        createMPConnection(st.getIdentifier(), st.getMyproxyUsername(), "", st.getLifetime());
    }

}
