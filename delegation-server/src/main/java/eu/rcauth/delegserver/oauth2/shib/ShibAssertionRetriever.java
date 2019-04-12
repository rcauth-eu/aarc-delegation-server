package eu.rcauth.delegserver.oauth2.shib;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;

public class ShibAssertionRetriever {

	public static final String SHIB_ASSERTION_COUNT="Shib-Assertion-Count";
	public static final String SHIB_ASSERTION="Shib-Assertion-";

	/**
	 * Log the SAML Assertions belonging to the current request into the transaction logs.
	 * This method will create an {@link UnverifiedConnectionFactory} to the Shibboleth SP
	 * running on 'localhost' to ask for the SAML Assertions via the {@link #SHIB_ASSERTION}
	 * links set in the request header.
	 *  
	 * @param request The original request
	 * @return A string with a single assertion per line
	 * @throws Throwable  In case the call to shibboleth fails.
	 */
	public static String getShibAssertions(HttpServletRequest request) throws Throwable {
			
		StringBuilder assertions = new StringBuilder();
		
		// create the factory for upcoming unverified connections
		// we cannot verify the https connections made to the Shibboleth SP because the called url is
		// 'localhost' which is not guaranteed to be present in the server certificate.
		UnverifiedConnectionFactory unverifiedConFactory = new UnverifiedConnectionFactory();
		
		// get the trace logger
    	//DSOA2ServiceEnvironment env =  (DSOA2ServiceEnvironment) environment;
    	//Logable traceLogger = env.getTraceLogger(); 
		
    	// get the number of assertions in the current request 
		String assCountHeader =  request.getHeader(SHIB_ASSERTION_COUNT);
		
		if ( assCountHeader != null && ! assCountHeader.isEmpty() ) {
		
			int assCount = Integer.parseInt( assCountHeader );
			for ( int i=1 ; i <= assCount; i++ ) {

				// for every assertion found construct to retrieval URL header name
				String assUrlHeaderName;
				if ( i < 10 ) {
					assUrlHeaderName = SHIB_ASSERTION + "0" + i;
				} else {
					assUrlHeaderName = SHIB_ASSERTION + i;					
				}
				
				// get the actual retrieval URL
				String assUrlString = request.getHeader(assUrlHeaderName );
				if ( assUrlString != null && ! assUrlString.isEmpty() ) {

					try {
					
						// execute a GET request to the retrieved URL
						URL  assURL = new URL(assUrlString);
						HttpsURLConnection assConnection = (HttpsURLConnection) assURL.openConnection();
						assConnection = unverifiedConFactory.getUnverifiedConnection(assConnection);
						
						InputStream assStream = assConnection.getInputStream();
						
					    BufferedReader rd = new BufferedReader(new InputStreamReader(assStream));
					    StringBuilder result = new StringBuilder();
					    String line;
					    
					    // aggregate results into a single buffer
					    while ((line = rd.readLine()) != null) {
					       result.append(line);
					    }
					    
					    rd.close();
						
					    // print SAML Assertion string builder
					    assertions.append(result.toString());
					    
					} catch (MalformedURLException e) {
						throw new Exception("Malformed URL while requesting Shibboleth Assertion" );
					} catch (IOException e) {
						throw new Exception("Request Error requesting Shibboleth Assertion for header \"" + assUrlString + "\": "+e.getMessage() );
					}
					
				} else {
					throw new Exception("Shibboleth Assertion URL " + assUrlHeaderName + " is empty! Ignoring..." );
				}
				
			}
			
		}
		
		return assertions.toString();
		
	}	
	
}
