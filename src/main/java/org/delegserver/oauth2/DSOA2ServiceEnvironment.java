package org.delegserver.oauth2;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Provider;

import org.delegserver.storage.DNRecordStore;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AuthorizationServletConfig;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandler;
import edu.uiuc.ncsa.security.servlet.UsernameTransformer;
import edu.uiuc.ncsa.security.util.mail.MailUtilProvider;

public class DSOA2ServiceEnvironment extends OA2SE {

	public DSOA2ServiceEnvironment(MyLoggingFacade logger, Provider<DNRecordStore> dnsp, Provider<TransactionStore> tsp, Provider<ClientStore> csp,
			int maxAllowedNewClientRequests, long rtLifetime, Provider<ClientApprovalStore> casp,
			List<MyProxyFacadeProvider> mfp, MailUtilProvider mup, MessagesProvider messagesProvider,
			Provider<AGIssuer> agip, Provider<ATIssuer> atip, Provider<PAIssuer> paip, Provider<TokenForge> tfp,
			HashMap<String, String> constants, AuthorizationServletConfig ac, UsernameTransformer usernameTransformer,
			boolean isPingable, int clientSecretLength, Map<String,Map<String,String>> scopesMap, ScopeHandler scopeHandler,
			boolean isRefreshTokenEnabled) {
		
		super(logger, tsp, csp, maxAllowedNewClientRequests, rtLifetime, casp, mfp, mup, messagesProvider, agip, atip, paip,
				tfp, constants, ac, usernameTransformer, isPingable, clientSecretLength, scopesMap.keySet(), scopeHandler,
				isRefreshTokenEnabled);
		
		this.dnsp = dnsp;
		this.scopesMap = scopesMap;
		
	}

	/* Environment provides a scopeMap extracted from configuration */
	
	protected Map<String,Map<String,String>> scopesMap;
	
	public Map<String,Map<String,String>> getScopesMap() {
		return scopesMap;
	}
	
	public Map<String,String> getClaimsMap(String scope) {
		return scopesMap.get(scope);
	}
	
	/* TODO: DNRecords */
	
	protected Provider<DNRecordStore> dnsp;
	protected DNRecordStore dnRecordStore;
	
	public DNRecordStore getDNRecordStore() {
		if ( dnRecordStore == null ) {
			dnRecordStore = dnsp.get();
		}
		return dnRecordStore;
	}

	
	
}
