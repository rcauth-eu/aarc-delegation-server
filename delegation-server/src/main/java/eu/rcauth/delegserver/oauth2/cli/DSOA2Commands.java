package eu.rcauth.delegserver.oauth2.cli;

import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2Commands;

import eu.rcauth.delegserver.oauth2.DSOA2ServiceEnvironment;
import eu.rcauth.delegserver.oauth2.loader.DSOA2ConfigurationLoader;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientStoreCommands;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;


public class DSOA2Commands extends OA2Commands {

    public DSOA2Commands(MyLoggingFacade logger) {
        super(logger);
    }

    /**
     * Do the same as the super class, but create an instance of
     * {@link DSOA2Commands} instead of {@link OA2Commands}
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
            DSOA2Commands oa2Commands = new DSOA2Commands(null);
            oa2Commands.start(args);
            CLIDriver cli = new CLIDriver(oa2Commands);
            cli.start();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        // use the Delegation Server configuration loader
        return new DSOA2ConfigurationLoader<>(getConfigurationNode(), getMyLogger());
    }

    @Override
    public ClientStoreCommands getNewClientStoreCommands() throws Exception {
        // use the Delegation Server Client Command processor
        DSOA2ServiceEnvironment se = (DSOA2ServiceEnvironment)getServiceEnvironment();
        DSOA2ClientCommands x = new DSOA2ClientCommands(getMyLogger(), "  ", se.getClientStore(), se.getClientApprovalStore());
        x.setRefreshTokensEnabled(se.isRefreshTokenEnabled());
        x.setSupportedScopes(se.getScopes());
        return x;
    }

}
