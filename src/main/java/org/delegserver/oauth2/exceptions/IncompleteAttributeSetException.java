package org.delegserver.oauth2.exceptions;

/**
 * Mismatch between the attribute set saved and attribute set present in the
 * request results in an  IncompleteAttributeSetException. This basically means
 * that an attribute that has been there before (and part of the attribute set 
 * saved in the trace records) is no longer present!
 * 
 * @author "Tamás Balogh"
 *
 */
public class IncompleteAttributeSetException extends Exception {

	public IncompleteAttributeSetException() {
		super();
	}
	
	public IncompleteAttributeSetException(String msg) {
		super(msg);
	}
}
