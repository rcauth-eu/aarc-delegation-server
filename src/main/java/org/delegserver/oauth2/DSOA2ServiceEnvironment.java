package org.delegserver.oauth2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Provider;

import org.delegserver.oauth2.generator.DNGenerator;
import org.delegserver.oauth2.generator.UniqueAttrGenerator;
import org.delegserver.storage.TraceRecord;
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

/**
 * A custom ServiceEnvironment implementation which adds a couple of extra this to the environment:
 * <p>
 * Scope Map : Maps claims and their sources into supported scopes. The upper (outer) map maps scopes to 
 * required claims, while the lower (inner) map maps individual claims to their source attribute.  
 * <p>
 * DN Generator : Used for generating user DNs based on source mapping from the configuration. 
 * <p>
 * TraceRecord Store Provider : Provider implementation for trace records (written after the model of 
 * already existing providers.
 * 
 * @author Tamás Balogh
 *
 */
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

	/* SCOPES AND CLAIMS  */
	
	/**
	 *  The scopes to claims mapping extracted from the configuration
	 */
	protected Map<String,Map<String,String>> scopesMap;
	
	/**
	 * Returns the complete scopes to claims mapping  
	 * @return scopes to claims mapping
	 */
	public Map<String,Map<String,String>> getScopesMap() {
		return scopesMap;
	}
	
	/**
	 * Returns the scope to claims to attribute source mapping for a specific scope 
	 * @param scope provided scope
	 * @return claims to attribute source mapping for the provided scope
	 */
	public Map<String,String> getClaimsMap(String scope) {
		return scopesMap.get(scope);
	}
	
	/* DN GENERATION */
	
	/**
	 *  Generates DNs from user attributes based on the DN sources loaded form configuration  
	 */
	protected DNGenerator dnGenerator = null;
	
	/**
	 *  Generates unique attribute lists and names from user attributes based on the DN 
	 *  sources specified in the configuration for {@link #dnGenerator}
	 */
	protected UniqueAttrGenerator uniqueAttrGenerator = null;
	
	/**
	 *  Unique Attribute List sources extracted from user configuration
	 */
	protected String[] uniqueAttrSources = null;

	/**
	 * Get DN Generator 
	 * @return DN Generator
	 */
	public DNGenerator getDnGenerator() {
		return dnGenerator;
	}
	
	/**
	 * Get Unique Attribute List Generator
	 * @return Unique Attribute List Generator
	 */
	public UniqueAttrGenerator getUniqueAttrGenerator() {
		if ( uniqueAttrGenerator == null ) {
			uniqueAttrGenerator = new UniqueAttrGenerator( getUniqueAttrSources() );
		}
		
		return uniqueAttrGenerator;
	}
	
	/** 
	 * Create Unique Attribute List Sources from an already existing {@link #dnGenerator}
	 * <p>
	 * The Unique Attribute List Sources is a simple concatenation of all the sources 
	 * that make up the CN: the user friendly display name part of the DN, and the unique ID
	 * part of the DN. This means that whatever source attribute is used to construct the 
	 * CN will be used in the Unique Attribute List as well to determine user uniqueness. 
	 * 
	 * @return unique attribute list sources
	 */
	protected String[] getUniqueAttrSources() {
		
		if ( uniqueAttrSources == null ) {
			
			List<String> attr = new ArrayList<String>();
			

			
			// add every display name source of the CN 
			for (Object source : dnGenerator.getCnNameSources()) {
				if ( source instanceof String ) {
					attr.add((String) source);
				} else if (source instanceof String[]) {
					// the source is multivalued, therefore it has to be decomposed 
					// into a list of single values 
					String[] sources = ((String[])source);
					attr.addAll( Arrays.asList(sources) );
				} else {
					throw new GeneralException("Could not parse DN sources properly!");
				}
			}
			
			// add every unique id source of the CN
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
	
	
	/* TRACE RECORD */
	
	/** 
	 * {@link org.delegserver.storage.TraceRecord} Store Provider creating TraceRecord Stores  
	 */
	protected Provider<TraceRecordStore> traceRecordSP;
	
	/**
	 * {@link org.delegserver.storage.TraceRecord} store
	 */
	protected TraceRecordStore<TraceRecord> traceRecordStore;
	
	/**
	 * Returns the {@link org.delegserver.storage.TraceRecord} store 
	 * @return {@link org.delegserver.storage.TraceRecord} store 
	 */
	public TraceRecordStore<TraceRecord> getTraceRecordStore() {
		if ( traceRecordStore == null ) {
			traceRecordStore = traceRecordSP.get();
		}
		return traceRecordStore;
	}

	
	
}
