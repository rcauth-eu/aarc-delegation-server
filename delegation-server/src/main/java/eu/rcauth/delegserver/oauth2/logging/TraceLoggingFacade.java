package eu.rcauth.delegserver.oauth2.logging;

import java.util.logging.Level;
import java.util.logging.Logger;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

/** 
 * The is a stateful Logger class that can log session specific log line 
 * which include a session identifier. The intended use of this class 
 * happens together with the {@link ThreadsafeTraceLogger} wrapper class,
 * which takes care of creating new {@link TraceLoggingFacade} instances
 * for every session. Thus making it possible to set stateful information
 * such as the session ID.
 * <p>
 * This logger logs according to the {@link LOG_FORMAT} format, which 
 * prepends the calling class name and the session identifier in front
 * of the original message.  
 * 
 * @author "Tamás Balogh"
 *
 */
public class TraceLoggingFacade extends MyLoggingFacade {

	protected static String MARK = "=============================================================================================================================================";
	protected static String LOG_FORMAT = "%20.20s [%s] %s"; 
	
    public TraceLoggingFacade(Logger logger) {
        super(logger);
    }

    public TraceLoggingFacade(String className, boolean debugOn) {
        super(className,debugOn);
    }

    public TraceLoggingFacade(String className) {
        super(className);
    }
    
    /* SESSION KEEPING */
    
    protected String sessionID = null;
    
    public void setSessionID(String sessionID) {
    	this.sessionID = String.valueOf( Math.abs( sessionID.hashCode() % 100000 ) );
	}
    
    public String getSessionID() {
		return sessionID;
	}

    /**
     * Clone the current object to a new instance. Note that every new
     * {@link TraceLoggingFacade} created this method will share the 
     * underlying {@link Logger} object. 
     * 
     * @return An identical clone of the current logger
     */
    public TraceLoggingFacade clone() {
    	TraceLoggingFacade clone = new TraceLoggingFacade( this.getLogger() );
    	clone.setClassName( this.getClassName() );
    	clone.setDebugOn( this.isDebugOn() );
    	
    	return clone;
    }
    
    /* OVERRIDEN METHODS */
    
    @Override
    public void setDebugOn(boolean debugOn) {
    	super.setDebugOn(debugOn);
    	if ( debugOn ) {
    		getLogger().setLevel(Level.FINE);
    	}
    }
    
    @Override
    public void debug(String x) {
        getLogger().fine(getFormattedMsg(x));
    }
    
    @Override
    public void info(String x) {
    	getLogger().info(getFormattedMsg(x));
    }
 
    @Override
    public void warn(String x) {
    	getLogger().warning(getFormattedMsg(x));
    }
    
    @Override
    public void error(String x) {
    	getLogger().severe(getFormattedMsg(x));
    }
    
    /* HELPER METHODS */
    
    /**
     * Put a marked message in the logs. This is intended to create logical separations 
     * in the logs. 
     * <p>
     * Note that depending on the debug level set the actual MARK lines might or might 
     * not appear.
     * 
     * @param x The message to highlight with a marking
     */
    public void marked(String x) {
    	getLogger().fine(getFormattedMsg(MARK));
    	getLogger().info(getFormattedMsg(x));
    	getLogger().fine(getFormattedMsg(MARK));
    }
    
    /**
     * Format message before outputing it to the underlying logger.
     * <p>
     * This method will append 2 additional elements in front of the
     * original log message:
     * <ul>
     * <li> 
     * The calling class name. This is calculated from the current exection
     * stack taking into account the wrapper method from {@link ThreadsafeTraceLogger}.
     * The formatting might break if you use this class without its intended wrapper
     * class.
     * </li>
     * 
     * <li>
     * The session identifier.
     * </li>
     * 
     * </ul>
     * 
     * @param msg The original log message
     * @return Formated message
     */
    protected String getFormattedMsg(String msg) {

    	StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    	// 0 - getStackTrace call
    	// 1 - getFormattedMsg
    	// 2 - debug/info/error/warn
    	// 3 - wrapper method in ThreadsafeTraceLogger
    	String fullClassName = stack[4].getClassName();
		String callingClassName = null;
		String[] callingClass = fullClassName.split("\\.");
	
		if ( callingClass == null || callingClass.length == 0 ) {
			callingClassName = "";
		} else {
			callingClassName = callingClass[ callingClass.length - 1 ];
		}
		
    	return String.format(LOG_FORMAT, callingClassName, sessionID, msg);
    }
    
}
