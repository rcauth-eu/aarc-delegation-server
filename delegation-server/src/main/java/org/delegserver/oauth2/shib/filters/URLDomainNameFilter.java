package org.delegserver.oauth2.shib.filters;

import java.net.MalformedURLException;
import java.net.URL;

public class URLDomainNameFilter implements ShibAttributeFilter {

	/**
	 * Try to parse a URL and return its domain name component. In case
	 * this method fails to convert to URL or extract the domain name
	 * it will simply return the original value 
	 * 
	 * @param value A URL
	 * @return The domain name of the URL
	 */
	@Override
	public String process(String value) {
		
		try {
		
			// try converting to a URL
			URL url = new URL(value);
			String host = url.getHost();
			
			// strip off the hostname form the domain name in
			// case there are more than two "."-s in the URL
			int firstDot = host.indexOf(".");
			if ( firstDot >= 0 && host.indexOf(".", firstDot+1) >= 0 ) {
				return host.substring(firstDot+1);
			} else {
				return host;
			}
			
		} catch (MalformedURLException e) {
			
			// in case the conversion fails, return the attribute as is
			return value;
		}
		
	}
	
}
