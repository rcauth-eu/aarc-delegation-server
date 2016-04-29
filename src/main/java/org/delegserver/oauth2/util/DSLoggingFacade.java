package org.delegserver.oauth2.util;

import java.util.logging.Level;
import java.util.logging.Logger;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

public class DSLoggingFacade extends MyLoggingFacade {

	protected final String mark = "=============================================================================================================================================";
	
    public DSLoggingFacade(Logger logger) {
        super(logger);
    }

    public DSLoggingFacade(String className, boolean debugOn) {
        super(className,debugOn);
        if ( debugOn ) {
        	getLogger().setLevel(Level.FINE);
        }
    }

    public DSLoggingFacade(String className) {
        super(className);
    }	
	
    @Override
    public void debug(String x) {
        getLogger().fine(x);
    }
    
    @Override
    public void info(String x) {
    	getLogger().info(x);
    }
 
    @Override
    public void warn(String x) {
    	getLogger().warning(x);
    }
    
    @Override
    public void error(String x) {
    	getLogger().severe(x);
    }
    
    public void marked(String x) {
    	getLogger().info(mark);
    	getLogger().info(x);
    	getLogger().info(mark);
    }
}
