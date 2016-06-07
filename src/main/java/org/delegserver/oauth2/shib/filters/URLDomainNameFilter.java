package org.delegserver.oauth2.shib.filters;

import java.net.MalformedURLException;
import java.net.URL;

public class URLDomainNameFilter implements ShibAttributeFilter {

	@Override
	public String process(String value) {
		
		try {
		
			// try converting to a URL
			URL url = new URL(value);
			return url.getHost();
			
		} catch (MalformedURLException e) {
			
			// in case the conversion fails, return the attribute as is
			return value;
		}
		
	}
	
}
