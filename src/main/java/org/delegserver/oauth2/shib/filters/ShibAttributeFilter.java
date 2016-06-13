package org.delegserver.oauth2.shib.filters;

/**
 * Attribute Filter interface. Implement this interface in case you're 
 * developing a new attribute filter class. Use your implementation class
 * in the server configuration to activate it. A single instance of the
 * filter class will be created automatically that will handle filtering
 * requests.
 * 
 * @author "Tamás Balogh"
 *
 */
public interface ShibAttributeFilter {

	/**
	 * Process the value of an attribute, and return the *new* processed value.
	 * 
	 * @param value The original value
	 * @return The processed value
	 */
	public String process(String value);
	
}
