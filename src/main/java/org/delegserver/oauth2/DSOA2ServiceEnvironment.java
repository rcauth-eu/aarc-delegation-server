package org.delegserver.oauth2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Provider;

import org.delegserver.storage.TraceRecordStore;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AuthorizationServletConfig;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
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

	public DSOA2ServiceEnvironment(MyLoggingFacade logger, Provider<TraceRecordStore> trsp, Provider<TransactionStore> tsp, Provider<ClientStore> csp,
			int maxAllowedNewClientRequests, long rtLifetime, Provider<ClientApprovalStore> casp,
			List<MyProxyFacadeProvider> mfp, MailUtilProvider mup, MessagesProvider messagesProvider,
			Provider<AGIssuer> agip, Provider<ATIssuer> atip, Provider<PAIssuer> paip, Provider<TokenForge> tfp,
			HashMap<String, String> constants, AuthorizationServletConfig ac, UsernameTransformer usernameTransformer,
			boolean isPingable, int clientSecretLength, Map<String,Map<String,String>> scopesMap, ScopeHandler scopeHandler,
			boolean isRefreshTokenEnabled, DNGenerator dnGenerator) {
		
		super(logger, tsp, csp, maxAllowedNewClientRequests, rtLifetime, casp, mfp, mup, messagesProvider, agip, atip, paip,
				tfp, constants, ac, usernameTransformer, isPingable, clientSecretLength, scopesMap.keySet(), scopeHandler,
				isRefreshTokenEnabled);
		
		this.traceRecordSP = trsp;
		this.scopesMap = scopesMap;
		this.dnGenerator = dnGenerator;
		
	}

	/* Environment provides a scopeMap extracted from configuration */
	
	protected Map<String,Map<String,String>> scopesMap;
	
	public Map<String,Map<String,String>> getScopesMap() {
		return scopesMap;
	}
	
	public Map<String,String> getClaimsMap(String scope) {
		return scopesMap.get(scope);
	}
	
	/* DN Generation sources */
	
	protected DNGenerator dnGenerator = null;
	protected UniqueAttrListGenerator uniqueAttrListGenerator = null;
	protected String[] uniqueAttrSources = null;

	public DNGenerator getDnGenerator() {
		return dnGenerator;
	}
	
	public UniqueAttrListGenerator getUniqueAttrListGenerator() {
		return uniqueAttrListGenerator;
	}
	
	public String[] getUniqueAttrSources() {
		
		if ( uniqueAttrSources == null ) {
			
			List<String> attr = new ArrayList<String>();
			
			for (Object source : dnGenerator.getCnNameSources()) {
				if ( source instanceof String ) {
					attr.add((String) source);
				} else if (source instanceof String[]) { 
					String[] sources = ((String[])source);
					attr.addAll( Arrays.asList(sources) );
				} else {
					throw new GeneralException("Could not parse DN sources properly!");
				}
			}
			
			for (Object source : dnGenerator.getCnUniqueIDSources()) {
				if ( source instanceof String ) {
					attr.add((String) source);
				} else if (source instanceof String[]) { 
					String[] sources = ((String[])source);
					attr.addAll( Arrays.asList(sources) );
				} else {
					throw new GeneralException("Could not parse DN sources properly!");
				}
			}	
			
			uniqueAttrSources = attr.toArray(new String[attr.size()]);
			
		}
		
		return uniqueAttrSources;
	}
	
	
	/* TODO: TraceRecords */
	
	protected Provider<TraceRecordStore> traceRecordSP;
	protected TraceRecordStore traceRecordStore;
	
	public TraceRecordStore getTraceRecordStore() {
		if ( traceRecordStore == null ) {
			traceRecordStore = traceRecordSP.get();
		}
		return traceRecordStore;
	}

	
	
}
