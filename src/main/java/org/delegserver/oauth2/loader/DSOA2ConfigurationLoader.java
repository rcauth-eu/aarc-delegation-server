package org.delegserver.oauth2.loader;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.delegserver.oauth2.DSOA2ConfigurationLoaderUtils;
import org.delegserver.oauth2.DSOA2ServiceEnvironment;
import org.delegserver.oauth2.DSOA2ServiceTransaction;
import org.delegserver.oauth2.util.DNRecordConverter;
import org.delegserver.storage.DNRecordKeys;
import org.delegserver.storage.DNRecordStore;
import org.delegserver.storage.DSOA2TConverter;
import org.delegserver.storage.DSOA2TransactionKeys;
import org.delegserver.storage.impl.DNRecordProvider;
import org.delegserver.storage.impl.MultiDNRecordStoreProvider;
import org.delegserver.storage.sql.DSOA2SQLTransactionStoreProvider;
import org.delegserver.storage.sql.DSSQLDNRecordStoreProvider;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2SQLTransactionStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.DSTransactionProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;

import javax.inject.Provider;

import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME_SPECIFIC_PART;
import static edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider.TRANSACTION_ID;

import java.util.Map;

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
                    getScopesMap(),
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

    
    @Override
    protected OA2SQLTransactionStoreProvider createSQLTSP(ConfigurationNode config,
													      ConnectionPoolProvider<? extends ConnectionPool> cpp,
													      String type,
													      MultiDSClientStoreProvider clientStoreProvider,
													      Provider<? extends OA2ServiceTransaction> tp,
													      Provider<TokenForge> tfp,
													      MapConverter converter){
    	return new DSOA2SQLTransactionStoreProvider(config,cpp,type,clientStoreProvider,tp,tfp,converter);
    }
    
    
    
    protected Map<String,Map<String,String>> scopes = null;
    
    public Map<String,Map<String,String>> getScopesMap() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        if (scopes == null) {
            scopes = DSOA2ConfigurationLoaderUtils.getScopesMap(cn);
        }
        return scopes;    
    }
    
    public static class MPST2Provider extends DSTransactionProvider<OA2ServiceTransaction> {

        public MPST2Provider(IdentifierProvider<Identifier> idProvider) {
            super(idProvider);
        }

        @Override
        public OA2ServiceTransaction get(boolean createNewIdentifier) {
        	return new DSOA2ServiceTransaction(createNewId(createNewIdentifier));
        }
        
    }

    @Override
    protected Provider<TransactionStore> getTSP() {
        IdentifiableProvider tp = new MPST2Provider(new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, TRANSACTION_ID, false));
        DSOA2TransactionKeys keys = new DSOA2TransactionKeys();
        DSOA2TConverter<DSOA2ServiceTransaction> tc = new DSOA2TConverter<DSOA2ServiceTransaction>(keys, tp, getTokenForgeProvider().get(), getClientStoreProvider().get());
        return getTSP(tp,  tc);
    }    
    
}
