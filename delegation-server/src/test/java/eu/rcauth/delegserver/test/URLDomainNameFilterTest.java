package eu.rcauth.delegserver.test;

import eu.rcauth.delegserver.oauth2.shib.filters.URLDomainNameFilter;

import org.junit.Test;

public class URLDomainNameFilterTest {

    @Test
    public void testURLASCIIConversion()   {
	URLDomainNameFilter filter = new URLDomainNameFilter();
	String[] input = {
	    "gopher://t\u00eatu.élpaaso.org",
	    "http://jdoe:password@\u8a00\u8a9e.net:80",
	    "ftp://host.\u6e2c\u8a66",
	    "ident://оживлённым.берегам.ru",
	    "test://ваше здоровье",
	    "urn:mace:пример:tést",
	    "ΑΡΙΣΤΟΤΕΛΕΙΟ ΠΑΝΕΠΙΣΤΗΜΙΟ ΘΕΣΣΑΛΟΝΙΚΗΣ"
	};

	for (String s : input) {
	    System.out.println("IN  : " + s);
	    System.out.println("OUT : " + filter.process(s));
	    System.out.println(" ================================ ");
	}

    }
}
