package org.delegserver.oauth2.logging;

import org.apache.commons.configuration.tree.ConfigurationNode;

import edu.uiuc.ncsa.security.core.util.LoggerProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import static edu.uiuc.ncsa.security.core.configuration.Configurations.getFirstNode;

import java.util.Date;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

public class TraceRecordLoggerProvider extends LoggerProvider {

	protected TraceLoggingFacade logger;
	protected ConfigurationNode configurationNode;

	public static final String TRACE_LOGGING_COMPONENT = "traceLogging";

	public static final String TRACE_LOGGING_FORMAT = "[%s] %5.5s %s" + System.getProperty("line.separator");

	
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
					
						return String.format(TRACE_LOGGING_FORMAT, (new Date()).toString(), 
																	rec.getLevel(),
																	formatMessage(rec));
					}
				});
				break;
			}
		}
		basicLogger.getLogger().removeHandler(logHandler);
		
		logger = new TraceLoggingFacade(loggerName, basicLogger.isDebugOn());
		logger.getLogger().addHandler(logHandler);
		logger.getLogger().setUseParentHandlers(false);
		
		
        return logger;
		
	}
}
