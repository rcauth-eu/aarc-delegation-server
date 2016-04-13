package org.delegserver.oauth2;

import edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigurationLoaderUtils;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.core.configuration.Configurations;

import org.apache.commons.configuration.tree.ConfigurationNode;

import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigTags.SCOPES;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.SCOPE;
import static org.delegserver.oauth2.DSConfigTags.SCOPE_NAME;
import static org.delegserver.oauth2.DSConfigTags.CLAIM_NAME;
import static org.delegserver.oauth2.DSConfigTags.SCOPE_CLAIM;

public class DSOA2ConfigurationLoaderUtils extends OA2ConfigurationLoaderUtils {

	// The key set of the outer map is the list of supported scopes
	// The inner maps contain the relevant claims for each scope and their source mapping to the SAML attributes  
    private static Map<String,Map<String,String>> scopesMap = null;
    
    // In case custom scopes configuration is available don't rely on hardcoded scopes.
    public static Map<String,Map<String,String>> getScopesMap(ConfigurationNode cn) throws ClassNotFoundException, IllegalAccessException, InstantiationException {
          if (scopesMap == null) {
              scopesMap = new HashMap<String, Map<String,String>>();
              
              // Get the scopes configured in the configuration file 
              // The scope names are no longer declared as <scope>scope_name</scope>
              // Instead we use <scope name="scope_name"></scope>
              if (0 < cn.getChildrenCount(SCOPES)) {
            	  
                  // we have custom scopes defined 
                  ConfigurationNode scopesNode = Configurations.getFirstNode(cn, SCOPES);
                  for (Object nodeI : scopesNode.getChildren(SCOPE)) {
                	  
                	  // extract scope name
                      ConfigurationNode scopeNode = (ConfigurationNode) nodeI;
                      String currentScope = Configurations.getFirstAttribute(scopeNode, SCOPE_NAME);
                      
                      Map<String,String> claims = null;
                      if (0 < scopeNode.getChildrenCount(SCOPE_CLAIM)) {
                  
                    	  // we have claims belonging to the current scope
                    	  claims = new HashMap<String,String>();
                    	  for (Object nodeJ : scopeNode.getChildren(SCOPE_CLAIM) ) {
                    		  ConfigurationNode claimNode = (ConfigurationNode) nodeJ;
                    		  String currentClaim = Configurations.getFirstAttribute(claimNode, CLAIM_NAME);
                    		  String currentClaimAttr  = (String) claimNode.getValue();
                    		  claims.put(currentClaim,currentClaimAttr);
                    	  }
                      }
                      
                      // save scope and claims
                      scopesMap.put(currentScope,claims);
                  }
                  
              } else {
            	  
            	  //default to hardcoded scopes with no claim mapping
            	  for (String s : OA2Scopes.basicScopes) {
                      scopesMap.put(s,null);
                  }
            	  
              }
          }
          return scopesMap;
      }
    
    
	
}
