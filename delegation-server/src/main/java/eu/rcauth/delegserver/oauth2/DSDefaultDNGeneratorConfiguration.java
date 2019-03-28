package eu.rcauth.delegserver.oauth2;

/**
 * This static class contains a default DN Generator configuration. This
 * configuration is only used in case there is no DN Generator sources 
 * are found in the server configuration.
 * 
 * @author "Tamás Balogh"
 *
 */
public class DSDefaultDNGeneratorConfiguration {

	/* Default CN Name candidates */
	
	private static Object[] defaultCnNameCandidates = null;
	
	public static String DEFAULT_DISPLAY_NAME="displayName";
	public static String DEFAULT_GIVEN_NAME="givenName";
	public static String DEFAULT_SN="sn";
	public static String DEFAULT_CN="cn";

	/* Default CN Unique ID candidates */
	
	private static Object[] defaultCnUniqueIDCandidates = null;
	
	public static String DEFAULT_EPUID="epuid";
	public static String DEFAULT_EPPN="eppn";
	public static String DEFAULT_EPTID="eptid";
	
	/* Default Organization candidates */
	
	private static Object[] defaultOrgCandidates = null;
	
	public static String DEFAULT_SCHAC_HOME_ORG="schacHomeOrganisation";
	public static String DEFAULT_ORG_DISPLAY_NAME="organisationDisplayName";
	public static String DEFAULT_ENTITY_ID="entityID";

	
	public static Object[] getDefaultCnNameCandidates() {
		
		if ( defaultCnNameCandidates == null ) {
			
			defaultCnNameCandidates = new Object[3];
			defaultCnNameCandidates[0] = DEFAULT_DISPLAY_NAME;
			defaultCnNameCandidates[1] = new String[] {DEFAULT_GIVEN_NAME, DEFAULT_SN};
			defaultCnNameCandidates[2] = DEFAULT_CN;
			
		}
		
		return defaultCnNameCandidates;
	}
	
	public static Object[] getDefaultCnUniqueIDCandidates() {
	
		if ( defaultCnUniqueIDCandidates == null ) {
			
			defaultCnUniqueIDCandidates = new Object[3];
			defaultCnUniqueIDCandidates[0] = DEFAULT_EPUID;
			defaultCnUniqueIDCandidates[1] = DEFAULT_EPPN;
			defaultCnUniqueIDCandidates[2] = DEFAULT_EPTID;			
			
		}
		
		return defaultCnUniqueIDCandidates;
	}
	
	
	public static Object[] getDefaultOrgCandidates() {
		
		if ( defaultOrgCandidates == null ) {
			
			defaultOrgCandidates = new Object[3];
			defaultOrgCandidates[0] = DEFAULT_SCHAC_HOME_ORG;
			defaultOrgCandidates[1] = DEFAULT_ORG_DISPLAY_NAME;
			defaultOrgCandidates[2] = DEFAULT_ENTITY_ID;
			
		}
		
		return defaultOrgCandidates;
	}
}

