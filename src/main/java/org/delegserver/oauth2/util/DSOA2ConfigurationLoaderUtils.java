package org.delegserver.oauth2.util;

import edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigurationLoaderUtils;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.core.configuration.Configurations;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.delegserver.oauth2.DSDefaultDNGeneratorConfiguration;

import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigTags.SCOPES;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.SCOPE;
import static org.delegserver.oauth2.DSConfigTags.*;

public class DSOA2ConfigurationLoaderUtils extends OA2ConfigurationLoaderUtils {

	// The key set of the outer map is the list of supported scopes
	// The inner maps contain the relevant claims for each scope and their
	// source mapping to the SAML attributes
	private static Map<String, Map<String, String>> scopesMap = null;

	// In case custom scopes configuration is available don't rely on hardcoded
	// scopes.
	public static Map<String, Map<String, String>> getScopesMap(ConfigurationNode cn)
			throws ClassNotFoundException, IllegalAccessException, InstantiationException {
		if (scopesMap == null) {
			scopesMap = new HashMap<String, Map<String, String>>();

			// Get the scopes configured in the configuration file
			// The scope names are no longer declared as
			// <scope>scope_name</scope>
			// Instead we use <scope name="scope_name"></scope>
			if (0 < cn.getChildrenCount(SCOPES)) {

				// we have custom scopes defined
				ConfigurationNode scopesNode = Configurations.getFirstNode(cn, SCOPES);
				for (Object nodeI : scopesNode.getChildren(SCOPE)) {

					// extract scope name
					ConfigurationNode scopeNode = (ConfigurationNode) nodeI;
					String currentScope = Configurations.getFirstAttribute(scopeNode, SCOPE_NAME);

					Map<String, String> claims = null;
					if (0 < scopeNode.getChildrenCount(SCOPE_CLAIM)) {

						// we have claims belonging to the current scope
						claims = new HashMap<String, String>();
						for (Object nodeJ : scopeNode.getChildren(SCOPE_CLAIM)) {
							ConfigurationNode claimNode = (ConfigurationNode) nodeJ;
							String currentClaim = Configurations.getFirstAttribute(claimNode, CLAIM_NAME);
							String currentClaimAttr = (String) claimNode.getValue();
							claims.put(currentClaim, currentClaimAttr);
						}
					}

					// save scope and claims
					scopesMap.put(currentScope, claims);
				}

			} else {

				// default to hardcoded scopes with no claim mapping
				for (String s : OA2Scopes.basicScopes) {
					scopesMap.put(s, null);
				}

			}
		}
		return scopesMap;
	}
	

	public static Object[] cnNameSources = null; 
	public static Object[] cnUniqueIDSources = null;
	public static Object[] orgSources = null;
	
	public static Object[] getCnNameSources(ConfigurationNode cn) {
		
		if ( cnNameSources == null ) {
			//parse config file for CN Name sources first
			cnNameSources = parseDnGenerator(cn, DN_GENERATOR_CN_NAME);
		} else {
			//fall back on default
			cnNameSources = DSDefaultDNGeneratorConfiguration.getDefaultCnNameCandidates();
		}
		
		return cnNameSources;
	}
	
	public static Object[] getCnUniqueIDSources(ConfigurationNode cn) {
		
		if ( cnUniqueIDSources == null ) {
			//parse config file for CN Unique ID sources first
			cnUniqueIDSources = parseDnGenerator(cn, DN_GENERATOR_CN_UNIQUE_ID);
		} else {
			//fall back on default
			cnUniqueIDSources = DSDefaultDNGeneratorConfiguration.getDefaultCnNameCandidates();
		}
		
		return cnUniqueIDSources;
	}	
	
	public static Object[] getOrgSources(ConfigurationNode cn) {
		
		if ( orgSources == null ) {
			//parse config file for CN Unique ID sources first
			orgSources = parseDnGenerator(cn, DN_GENERATOR_ORGANISATION);
		} else {
			//fall back on default
			orgSources = DSDefaultDNGeneratorConfiguration.getDefaultCnNameCandidates();
		}
		
		return orgSources;
	}		
	
	public static Map<String,String> getExtensionSources(ConfigurationNode cn) {

		Map<String,String> sources  = new HashMap<String,String>();
		if (0 < cn.getChildrenCount( DN_GENERATOR )) {
			
			// we have a dnGenerator tag!
			ConfigurationNode dnGenratorNode = Configurations.getFirstNode(cn, DN_GENERATOR);
			if (0 < dnGenratorNode.getChildrenCount( DN_GENERATOR_EXTENSIONS )) {
				
				// we have a dn component tag!
				ConfigurationNode cnNameNode = Configurations.getFirstNode(dnGenratorNode, DN_GENERATOR_EXTENSIONS);
				int sourceCount = cnNameNode.getChildrenCount( DN_GENERATOR_SOURCE );
				if (0 < sourceCount) {
					
					for ( int i=0 ; i<sourceCount ; i++ ) {
						
						ConfigurationNode sourceNode = (ConfigurationNode) cnNameNode.getChild(i);
						String sourceName = (String) Configurations.getFirstAttribute(sourceNode, DN_GENERATOR_SOURCE_NAME);
						String source = (String) sourceNode.getValue();
						
						sources.put(sourceName, source);
					}
				}
			}
		}	
		
		return sources;
		
	}
	
	/* private method for extracting DN sources */
	
	private static String DN_SOURCE_SEPARATOR = "+";
	
	private static Object[] parseDnGenerator(ConfigurationNode cn, String dnComponent) {
		
		Object[] sources  = null;
		if (0 < cn.getChildrenCount( DN_GENERATOR )) {
			
			// we have a dnGenerator tag!
			ConfigurationNode dnGenratorNode = Configurations.getFirstNode(cn, DN_GENERATOR);
			if (0 < dnGenratorNode.getChildrenCount( dnComponent )) {
				
				// we have a dn component tag!
				ConfigurationNode cnNameNode = Configurations.getFirstNode(dnGenratorNode, dnComponent);
				int sourceCount = cnNameNode.getChildrenCount( DN_GENERATOR_SOURCE );
				if (0 < sourceCount) {
				
					sources = new Object[sourceCount];
					for ( int i=0 ; i<sourceCount ; i++ ) {
						
						ConfigurationNode sourceNode = (ConfigurationNode) cnNameNode.getChild(i);
						String source = (String) sourceNode.getValue();
						
						//look out for multi-values separated with a + sign
						if ( source.contains(DN_SOURCE_SEPARATOR) ) {
							sources[i] = source.split("\\" + DN_SOURCE_SEPARATOR);
						} else {
							sources[i] = source;
						}
					}
				}
			}
		}
		return sources;
	}
	
}
