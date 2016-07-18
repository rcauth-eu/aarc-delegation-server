package org.delegserver.oauth2.exceptions;


/**
 * Exceptions thrown whne there is no trace record found for a user.
 * 
 * @author "Tamás Balogh"
 *
 */
public class NoTraceRecordException extends Exception {

	public NoTraceRecordException() {
		super();
	}
	
	public NoTraceRecordException(String msg) {
		super(msg);
	}
	
}
