package org.delegserver.oauth2.shib.filters;

public class ShoutFilter implements ShibAttributeFilter {

	@Override
	public String process(String value) {
		return value.toUpperCase();
	}

}
