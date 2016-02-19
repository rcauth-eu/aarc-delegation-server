package org.delegserver.oauth2.loader;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.util.DNRecordConverter;
import org.delegserver.storage.DNRecordKeys;
import org.delegserver.storage.DNRecordStore;
import org.delegserver.storage.impl.DNRecordProvider;
import org.delegserver.storage.impl.MultiDNRecordStoreProvider;
import org.delegserver.storage.sql.DSSQLDNRecordStoreProvider;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import javax.inject.Provider;

import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME_SPECIFIC_PART;

public class DSOA2ConfigurationLoader<T extends ServiceEnvironmentImpl> extends OA2ConfigurationLoader<T> {

	public DSOA2ConfigurationLoader(ConfigurationNode node) {
		super(node);
	}
	
	public DSOA2ConfigurationLoader(ConfigurationNode node, MyLoggingFacade logger) {
		super(node,logger);
	}
	
    @Override
    public T createInstance() {
        try {
            return (T) new DSOA2ServiceEnvironment(loggerProvider.get(),
            		getDNStoreProvider(),
                    getTransactionStoreProvider(),
                    getClientStoreProvider(),
                    getMaxAllowedNewClientRequests(),
                    getRTLifetime(),
                    getClientApprovalStoreProvider(),
                    getMyProxyFacadeProvider(),
                    getMailUtilProvider(),
                    getMP(),
                    getAGIProvider(),
                    getATIProvider(),
                    getPAIProvider(),
                    getTokenForgeProvider(),
                    getConstants(),
                    getAuthorizationServletConfig(),
                    getUsernameTransformer(),
                    getPingable(),
                    getClientSecretLength(),
                    getScopes(),
                    getScopeHandler(),
                    isRefreshTokenEnabled());
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            throw new GeneralException("Error: Could not create the runtime environment", e);
        }
    }	
	
    protected MultiDNRecordStoreProvider dnsp;
    
    public final static String DNRECORD_ID = "dnRecord";
    
    public Provider<DNRecordStore> getDNStoreProvider() {
    	if ( dnsp == null ) {
    		 dnsp = new MultiDNRecordStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get(), null, null);
    		 
    		 DNRecordProvider provider = new DNRecordProvider( new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, DNRECORD_ID, false ));
    		 DNRecordConverter converter = new DNRecordConverter( new DNRecordKeys(), provider);

    		 dnsp.addListener( new DSSQLDNRecordStoreProvider(cn,
    				  getMySQLConnectionPoolProvider(),
					  OA4MPConfigTags.MYSQL_STORE, 
					  converter, 
					  provider) );    	
    		 
    		 dnsp.addListener( new DSSQLDNRecordStoreProvider(cn,
   				  getMariaDBConnectionPoolProvider(),
					  OA4MPConfigTags.MARIADB_STORE, 
					  converter, 
					  provider) );      		 
    		 
    		 dnsp.addListener( new DSSQLDNRecordStoreProvider(cn,
    				  getPgConnectionPoolProvider(),
    				  OA4MPConfigTags.POSTGRESQL_STORE, 
    				  converter, 
    				  provider) );
    		 
    		 
    	}
    	return dnsp;
    }
    
}
