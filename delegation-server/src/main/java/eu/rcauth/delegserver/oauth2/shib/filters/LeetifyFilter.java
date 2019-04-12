package eu.rcauth.delegserver.oauth2.shib.filters;

public class LeetifyFilter implements ShibAttributeFilter {

	protected final String[] leet = {"4", "8", "(", ")", "3", "}", "6", "#", "!", "]", "X", "|", "M", "N", "0", "9", "Q", "2", "Z", "7", "U", "V", "W", "X", "J", "Z"};
	
	@Override
	public String process(String value) {
		
	    String str = value.toUpperCase(); // convert all to upper case so that you don't need equalsIgnoreCase()
	    
	    StringBuilder result = new StringBuilder();
	    
	    for (int i = 0; i < str.length(); ++i) {
	    	
	    	int leetIdx = str.charAt(i) - 'A';
	    	
	    	if ( leetIdx >= 0 && leetIdx < leet.length) {
	    		result.append(leet[str.charAt(i) - 'A']);
	    	} else {
	    		result.append(str.charAt(i));
	    	}
	    }
	    
	    return result.toString();
	}

}
