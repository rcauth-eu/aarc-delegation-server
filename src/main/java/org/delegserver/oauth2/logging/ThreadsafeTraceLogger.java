package org.delegserver.oauth2.logging;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import edu.uiuc.ncsa.security.core.Logable;

/**
 * Thread safe wrapper class for {@link TraceLoggingFacade}. The point of 
 * this wrapper class is to create new  {@link TraceLoggingFacade} objects
 * for every thread (session). Every session specific  {@link TraceLoggingFacade}
 * object has a specific session ID which is used for distinguishing log
 * messages by session.
 * <p>
 * Before using this logger you should initialize it with the current session
 * by using the {@link #initSessionLogger(String)} method. Than, you can happily log using
 * the appropriate log level methods. 
 * <p>
 * DO NOT FORGET! You should clean up the session specific logger when the session
 * ends using the {@link #destroySessionLogger()} method. If you fail to do so, you
 * will end up hoarding logger of expired sessions!
 * <p>
 * TODO: Isn't there a better way to destroy these objects automatically once the thread
 * ends?
 * 
 * @author "Tamás Balogh"
 *
 */
public class ThreadsafeTraceLogger implements Logable {

	/* Thread-safe map of session loggers */
	private Map<String,TraceLoggingFacade> sessionLoggers = null;
	
	/* The original logger object created by the configuration loader 
	 * Subsequent session loggers are cloned from this object
	 */
	private TraceLoggingFacade originalLogger = null;
	
	/* CONSTUCTORS */
	
	public ThreadsafeTraceLogger(TraceLoggingFacade originalLogger) {
		this.originalLogger = originalLogger;
		this.sessionLoggers = new ConcurrentHashMap<String,TraceLoggingFacade>();
	}
	
	/* SESSION KEEPING LOGS */

	/**
	 * Used to initialize a session logger. This method will clone the 
	 * original logger created by the {@link TraceRecordLoggerProvider}.
	 * The cloned, session specific, logger will be marked by the 
	 * sessionID provided. 
	 * 
	 * @param sessionID The sessionID to use to distinguish sessions
	 */
	public void initSessionLogger(String sessionID) {
		TraceLoggingFacade logger = getSessionLogger();
		logger.setSessionID(sessionID);
	}

	/**
	 * Destroy the session specific logger belonging to the current 
	 * thread.
	 * <p>
	 * DO NOT FORGET! You should clean up the session specific logger 
	 * when the session ends using the {@link #destroySessionLogger()} 
	 * method. If you fail to do so, you will end up hoarding logger of 
	 * expired sessions!
	 */
	public void destroySessionLogger() {
		String threadID = String.valueOf( Thread.currentThread().getId() );
		sessionLoggers.remove(threadID);
	}
	
	/**
	 * Get a session specific logger. This method will create a new logger
	 * for the calling thread. Before using the logger itself you should
	 * initialize it with a session identifier by calling {@link #initSessionLogger(String)}
	 * 
	 * @return The session specific logger
	 */
	protected TraceLoggingFacade getSessionLogger() {
		String threadID = String.valueOf( Thread.currentThread().getId() );
		if ( ! sessionLoggers.containsKey(threadID) ) {
			sessionLoggers.put( threadID ,  originalLogger.clone() );
		}
		return sessionLoggers.get(threadID);
	}
	
	/* REGULAR LOGGER METHODS */
	
	@Override
	public void debug(String msg) {
		getSessionLogger().debug(msg);
	}
	
	@Override
	public void info(String msg) {
		getSessionLogger().info(msg);
	}
	
	@Override
	public void warn(String msg) {
		getSessionLogger().warn(msg);
	}
	
	@Override
	public void error(String msg) {
		getSessionLogger().error(msg);
	}

	public void marked(String msg) {
		getSessionLogger().marked(msg);		
	}
	
	@Override
	public boolean isDebugOn() {
		return originalLogger.isDebugOn();
	}

	@Override
	public void setDebugOn(boolean setOn) {
		originalLogger.setDebugOn(setOn);
	}
	
}
