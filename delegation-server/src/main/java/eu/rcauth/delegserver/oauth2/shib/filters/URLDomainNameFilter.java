package eu.rcauth.delegserver.oauth2.shib.filters;

import java.net.URISyntaxException;
import java.net.URI;

import com.ibm.icu.text.IDNA;

public class URLDomainNameFilter implements ShibAttributeFilter {
    private static final IDNA idna = IDNA.getUTS46Instance(IDNA.DEFAULT);

    /**
     * Try to parse a URI. If it is not a URL, return the original value.
     * If it is a URL try to get the (punycode) domain name.
     * In case the punycode encoding fails, return the non-punycode hostname.
     * If the (punycode) hostname contains 2 or more dots, return the domain
     * part, otherwise the (punycode) hostname.
     * 
     * @param value A URI
     * @return The domain name of the URL
     */
    @Override
    public String process(String value) {
	try {
	    // try converting to a URI, throws URISyntaxException
	    URI uri = new URI(value);

	    // Is it a URL? Note that java.net.URL only works for some schemes,
	    // e.g. not for gopher://
	    if (uri.getRawSchemeSpecificPart().startsWith("//"))    {
		// It's a URL

		// Get raw authority, getHost() does not work on UTF-8
		// unfortunately. So we will remove userinfo and port by hand.
		String host = uri.getRawAuthority();

		// remove user:password part if present
		int startHost = host.indexOf("@");
		if (startHost > -1)    {
		    host = host.substring(startHost+1);
		}
		// remove port part if present
		int startPort = host.indexOf(":");
		if (startPort > -1)	{
		    host = host.substring(0,startPort);
		}

		// Return original if there is nothing left
		if (host.isEmpty())   {
		    return value;
		}

		// Now do punycode encoding
		final IDNA.Info info = new IDNA.Info();
		final StringBuilder idn_host = new StringBuilder();
		idna.nameToASCII(host, idn_host, info);
		if (info.hasErrors())   { // Cannot convert, leave as-is
		    return host;
		}

		// If we have more than 1 dots, strip off the hostname and return
		// the remaining domain name. Otherwise, just return as-is.
		int firstDot = idn_host.indexOf(".");
		if (firstDot > -1 && idn_host.indexOf(".", firstDot+1) > -1)	{
		    return idn_host.substring(firstDot+1);
		} else {    // 0 or 1 dots: return as-is
		    return idn_host.toString();
		}
	    } else {
		// It's not a URL but a URN, just return it
		return value;
	    }
	} catch (URISyntaxException e)	{
	    // Neither URN nor URI, just return
	    return value;
	}
    }
}
