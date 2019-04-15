package eu.rcauth.delegserver.oauth2.loader;

import eu.rcauth.delegserver.storage.*;
import eu.rcauth.delegserver.oauth2.DSOA2ServiceEnvironment;
import eu.rcauth.delegserver.oauth2.DSOA2ServiceTransaction;
import eu.rcauth.delegserver.oauth2.generator.CertExtensionGenerator;
import eu.rcauth.delegserver.oauth2.generator.DNGenerator;
import eu.rcauth.delegserver.oauth2.logging.ThreadsafeTraceLogger;
import eu.rcauth.delegserver.oauth2.logging.TraceLoggingFacade;
import eu.rcauth.delegserver.oauth2.logging.TraceRecordLoggerProvider;
import eu.rcauth.delegserver.oauth2.util.DSOA2ConfigurationLoaderUtils;
import eu.rcauth.delegserver.storage.impl.TraceRecordProvider;
import eu.rcauth.delegserver.storage.impl.DSOA2ClientProvider;
import eu.rcauth.delegserver.storage.impl.MultiTraceRecordStoreProvider;
import eu.rcauth.delegserver.storage.sql.DSOA2ClientSQLStoreProvider;
import eu.rcauth.delegserver.storage.sql.DSOA2SQLTransactionStoreProvider;
import eu.rcauth.delegserver.storage.sql.SQLTraceRecordStoreProvider;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2SQLTransactionStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.DSTransactionProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.ClientMemoryStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;

import org.apache.commons.configuration.tree.ConfigurationNode;

import java.util.Map;
import javax.inject.Provider;

import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME_SPECIFIC_PART;
import static edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider.TRANSACTION_ID;

import static eu.rcauth.delegserver.oauth2.DSConfigTags.*;


/**
 * Custom Configuration Loader. This has been extended with the following functions:
 * <p>
 *  - Configure the Trace Record Store backend based on the provided server configuration
 * <p>
 *  - Create custom Service Environment {@link DSOA2ServiceEnvironment} on demand
 * <p>
 *  - Load Scopes to Claims(and Attributes) mapping from configuration into environment
 * <p>
 *  - Load the DN Generator sources from the configuration into the environment
 * <p>
 *  - Load and instantiate Attribute Filters
 *
 * @author "Tamás Balogh"
 *
 * @param <T> This should be the custom Service Environment {@link DSOA2ServiceEnvironment}
 */
public class DSOA2ConfigurationLoader<T extends ServiceEnvironmentImpl> extends OA2ConfigurationLoader<T> {

    public DSOA2ConfigurationLoader(ConfigurationNode node) {
        super(node);
    }

    public DSOA2ConfigurationLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node,logger);
    }

    @Override
    @SuppressWarnings("unchecked")
    public T createInstance() {
        try {
            // Note we suppress an unchecked cast to T
            T se = (T) new DSOA2ServiceEnvironment(loggerProvider.get(),
                    getTraceRecordStoreProvider(),
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
                    getMpp(),   // see OA2ConfigurationLoader, we suppress an unchecked assignment
                    getMacp(),  // see OA2ConfigurationLoader, we suppress an unchecked assignment
                    getClientSecretLength(),
                    getScopesMap(),
                    getClaimSource(),
                    getLdapConfiguration(),
                    isRefreshTokenEnabled(),
                    isTwoFactorSupportEnabled(),
                    getMaxClientRefreshTokenLifetime(),
                    getJSONWebKeys(),   // see OA2ConfigurationLoader
                    getDNGenerator(),
                    getCertExtGenerator(),
                    getThreadsafeTraceLogger(),
                    getIssuer(),
                    isUtilServerEnabled(),
                    isOIDCEnabled());   // see OA2ConfigurationLoader
            if (getClaimSource() instanceof BasicClaimsSourceImpl) {
                ((BasicClaimsSourceImpl) getClaimSource()).setOa2SE((DSOA2ServiceEnvironment) se);
            }
            return se;
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            throw new GeneralException("Error: Could not create the runtime environment", e);
        }
    }

    /* Configure backend provider for TraceRecords */

    protected MultiTraceRecordStoreProvider<TraceRecord> traceRecordSP;

    public Provider<TraceRecordStore<TraceRecord>> getTraceRecordStoreProvider() {
        if ( traceRecordSP == null ) {
            traceRecordSP = new MultiTraceRecordStoreProvider<>(cn, isDefaultStoreDisabled(), loggerProvider.get(), null, null);

            TraceRecordIdentifierProvider<Identifier> idProv = new TraceRecordIdentifierProvider<>();

            TraceRecordProvider<TraceRecord> provider = new TraceRecordProvider<>( idProv );
            TraceRecordKeys keys = new TraceRecordKeys();
            TraceRecordConverter<TraceRecord> converter = new TraceRecordConverter<>( keys, provider);

            traceRecordSP.addListener( new SQLTraceRecordStoreProvider<>(cn,
                    getMySQLConnectionPoolProvider(),
                    OA4MPConfigTags.MYSQL_STORE,
                    converter,
                    provider) );

            traceRecordSP.addListener( new SQLTraceRecordStoreProvider<>(cn,
                    getMariaDBConnectionPoolProvider(),
                    OA4MPConfigTags.MARIADB_STORE,
                    converter,
                    provider) );

            // TODO: The backend for this is not written. yet. But it might just work out of the box
            /*
            traceRecordSP.addListener( new SQLTraceRecordStoreProvider(cn,
                    getPgConnectionPoolProvider(),
                    OA4MPConfigTags.POSTGRESQL_STORE,
                    converter,
                    provider) );
            */

        }
        return traceRecordSP;
    }


    /* Configure the use of custom Service Transaction implementation */


    public static class DSST2Provider extends DSTransactionProvider<OA2ServiceTransaction> {

        public DSST2Provider(IdentifierProvider<Identifier> idProvider) {
            super(idProvider);
        }

        @Override
        public OA2ServiceTransaction get(boolean createNewIdentifier) {
            return new DSOA2ServiceTransaction(createNewId(createNewIdentifier));
        }

    }

    @Override
    protected Provider<TransactionStore> getTSP() {
        IdentifierProvider idProv = new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, TRANSACTION_ID, false);
        // Note we suppress an unchecked assignment since OA4MPIdentifierProvider does not use generics
        @SuppressWarnings("unchecked")
        IdentifiableProvider tp = new DSST2Provider( idProv );
        DSOA2TransactionKeys keys = new DSOA2TransactionKeys();
        // Note we suppress an uncheck assignment in the 2nd and 4th parameters
        @SuppressWarnings("unchecked")
        DSOA2TConverter<DSOA2ServiceTransaction> tc = new DSOA2TConverter<DSOA2ServiceTransaction>(keys, tp, getTokenForgeProvider().get(), getClientStoreProvider().get());
        return getTSP(tp,  tc);
    }

    @Override
    protected OA2SQLTransactionStoreProvider createSQLTSP(ConfigurationNode config,
                                                          ConnectionPoolProvider<? extends ConnectionPool> cpp,
                                                          String type,
                                                          MultiDSClientStoreProvider clientStoreProvider,
                                                          Provider<? extends OA2ServiceTransaction> tp,
                                                          Provider<TokenForge> tfp,
                                                          MapConverter converter){
        return new DSOA2SQLTransactionStoreProvider<>(config,cpp,type,clientStoreProvider,tp,tfp,converter);
    }

    /* Configure the use of custom Client implementation */

    @Override
    protected MultiDSClientStoreProvider getCSP() {
        if (csp == null) {
            MapConverter<? extends Client> dsoa2ClientConverter = new DSOA2ClientConverter<>(getClientProvider());

            // Note we need a bare MapConverter as argument to DSFSClientStoreProvider()
            @SuppressWarnings("unchecked")
            MapConverter<Client> converter = (MapConverter<Client>)dsoa2ClientConverter;

            csp = new MultiDSClientStoreProvider<>(cn, isDefaultStoreDisabled(), loggerProvider.get(), null, null, getClientProvider());

            csp.addListener(new DSFSClientStoreProvider(cn, converter, getClientProvider()));
            csp.addListener(new DSOA2ClientSQLStoreProvider<>(getMySQLConnectionPoolProvider(),
                    OA4MPConfigTags.MYSQL_STORE,
                    converter, getClientProvider()));
            csp.addListener(new DSOA2ClientSQLStoreProvider<>(getMariaDBConnectionPoolProvider(),
                    OA4MPConfigTags.MARIADB_STORE,
                    converter, getClientProvider()));
            csp.addListener(new DSOA2ClientSQLStoreProvider<>(getPgConnectionPoolProvider(),
                    OA4MPConfigTags.POSTGRESQL_STORE,
                    converter, getClientProvider()));
            csp.addListener(new TypedProvider<ClientStore>(cn, OA4MPConfigTags.MEMORY_STORE, OA4MPConfigTags.CLIENTS_STORE) {
                @Override
                public Object componentFound(CfgEvent configurationEvent) {
                    if (checkEvent(configurationEvent))
                        return get();
                    return null;
                }

                @Override
                public ClientStore get() {
                    return new ClientMemoryStore<>(getClientProvider());
                }
            });
        }
        return csp;
    }

    @Override
    public IdentifiableProvider<? extends DSOA2Client> getClientProvider() {
        IdentifierProvider idp = new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, OA2Constants.CLIENT_ID, false);
        // Note we suppress an unchecked assignment since OA4MPIdentifierProvider does not use generics
        @SuppressWarnings("unchecked")
        DSOA2ClientProvider<DSOA2Client> cp = new DSOA2ClientProvider<DSOA2Client>(idp);
        return cp;
    }

    /* Load scope configuration with claim mapping */

    protected Map<String,Map<String,String>> scopes = null;

    public Map<String,Map<String,String>> getScopesMap() {
        if (scopes == null)
            scopes = DSOA2ConfigurationLoaderUtils.getScopesMap(cn);
        return scopes;
    }

    /* Load DN generator configuration with DN sources */

    DNGenerator dnGenerator = null;

    public DNGenerator getDNGenerator() {

        if ( dnGenerator == null ) {
            dnGenerator = new DNGenerator( DSOA2ConfigurationLoaderUtils.getCnNameSources(cn),
                    DSOA2ConfigurationLoaderUtils.getCnUniqueIDSources(cn),
                    DSOA2ConfigurationLoaderUtils.getOrgSources(cn),
                    DSOA2ConfigurationLoaderUtils.getAttributeFilters(cn),
                    getThreadsafeTraceLogger() );

            // load any additional attributes required for DN generation
            if (0 < cn.getChildrenCount( DN_GENERATOR )) {

                // we have a dnGenerator tag!
                ConfigurationNode dnGeneratorNode = Configurations.getFirstNode(cn, DN_GENERATOR);
                String dnType = Configurations.getFirstAttribute(dnGeneratorNode, DN_GENERATOR_TYPE );
                String baseDN = Configurations.getFirstAttribute(dnGeneratorNode, DN_GENERATOR_BASE_DN );
                String attr = Configurations.getFirstAttribute(dnGeneratorNode, DN_GENERATOR_ATTRIBUTE );

                if ( attr == null )
                    throw new GeneralException("Missing mandatory attribute 'attributeName' from the DN Generator");

                dnGenerator.setAttributeName(attr);

                if ( dnType == null ) {
                    // default to RFC2253
                    dnGenerator.setBaseDNRFC2253( baseDN );
                } else if ( dnType.equals( DNGenerator.DN_TYPE_OPENSSL ) ) {
                    dnGenerator.setBaseDNOpenSSL( baseDN );
                    dnGenerator.setDnType(dnType);
                } else if ( dnType.equals( DNGenerator.DN_TYPE_RFC2253 ) ) {
                    dnGenerator.setBaseDNRFC2253( baseDN );
                    dnGenerator.setDnType(dnType);
                } else {
                    throw new GeneralException("Unsupported 'type' attribute in DN Generator configuration!");
                }
            }

        }
        return dnGenerator;
    }

    public CertExtensionGenerator certExtGenerator = null;

    public CertExtensionGenerator getCertExtGenerator() {
        if ( certExtGenerator == null ) {
            Map<String, String> sourceMap = DSOA2ConfigurationLoaderUtils.getExtensionSources(cn);
            certExtGenerator = new CertExtensionGenerator(sourceMap, getThreadsafeTraceLogger());
        }
        return certExtGenerator;
    }

    /* TRACE LOGGING */

    protected TraceLoggingFacade traceLogger = null;
    protected ThreadsafeTraceLogger threadsafeTraceLogger = null;

    protected TraceLoggingFacade getTraceLogger() {

        if ( traceLogger == null ) {
            TraceRecordLoggerProvider provider = new TraceRecordLoggerProvider(cn);
            traceLogger =  (TraceLoggingFacade) provider.get();
        }

        return traceLogger;
    }

    protected ThreadsafeTraceLogger getThreadsafeTraceLogger() {

        if ( threadsafeTraceLogger == null )
            threadsafeTraceLogger =  new ThreadsafeTraceLogger( getTraceLogger() );

        return threadsafeTraceLogger;
    }

}
