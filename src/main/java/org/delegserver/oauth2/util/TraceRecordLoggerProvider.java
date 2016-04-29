package org.delegserver.oauth2.util;

import org.apache.commons.configuration.tree.ConfigurationNode;

import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.util.LoggerProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import static edu.uiuc.ncsa.security.core.configuration.Configurations.getFirstNode;

import java.util.Date;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

public class TraceRecordLoggerProvider extends LoggerProvider {

	protected DSLoggingFacade logger;
	protected ConfigurationNode configurationNode;

	public static final String TRACE_LOGGING_COMPONENT = "traceLogging";

	public static final String TRACE_LOGGING_FORMAT = "[%s] %7.7s  %20.20s  %s" + System.getProperty("line.separator");

	public TraceRecordLoggerProvider(ConfigurationNode configurationNode) {
		super(getFirstNode(configurationNode, TRACE_LOGGING_COMPONENT));
	}

	@Override
	public MyLoggingFacade get() {
		MyLoggingFacade basicLogger = super.get();

		String loggerName = basicLogger.getLogger().getName();
		FileHandler logHandler = null;
		
		for (Handler h : basicLogger.getLogger().getHandlers() ) {
			if ( h instanceof FileHandler ) {
				logHandler = (FileHandler) h;
				logHandler.setFormatter(new Formatter() {
					
					@Override
					public String format(LogRecord rec) {
					
						String callingClassName = null;
						String[] callingClass = rec.getSourceClassName().split("\\.");
					
						if ( callingClass == null || callingClass.length == 0 ) {
							callingClassName = "";
						} else {
							callingClassName = callingClass[ callingClass.length - 1 ];
						}
						
						return String.format(TRACE_LOGGING_FORMAT, (new Date()).toString(), 
																	rec.getLevel(),
																	callingClassName,
																	formatMessage(rec));
					}
				});
				break;
			}
		}
		basicLogger.getLogger().removeHandler(logHandler);
		
		logger = new DSLoggingFacade(loggerName, basicLogger.isDebugOn());
		logger.getLogger().addHandler(logHandler);
		logger.getLogger().setUseParentHandlers(false);
		
		
        return logger;
		
	}
}
