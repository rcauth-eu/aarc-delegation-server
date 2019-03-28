package eu.rcauth.delegserver.oauth2.shib.filters;

public class MissepllFilter implements ShibAttributeFilter {

	@Override
	public String process(String value) {
		
		int hash = value.hashCode();
		int len = value.length();
		
		int char1 = hash % len;
		int char2 = 0;
		
		if ( char1 == 0 ) {
			char2 = 1;
		} else if ( char1 == len - 1 ) {
			char2 = len - 2;
		} else {
			char2 = char1 + 1;
		}
		
		char letter1 = value.charAt(char1);
		char letter2 = value.charAt(char2);
		char[] letters = value.toCharArray();
		letters[ char2 ] = letter1;
		letters[ char1 ] = letter2;
		
		return String.valueOf(letters);
	}

}
