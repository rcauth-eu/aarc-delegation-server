package eu.rcauth.delegserver.storage.sql;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2ClientSQLStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.SQLClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table.ClientStoreTable;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import edu.uiuc.ncsa.security.delegation.storage.Client;

import javax.inject.Provider;

import eu.rcauth.delegserver.storage.DSOA2Client;
import eu.rcauth.delegserver.storage.DSOA2ClientKeys;
import eu.rcauth.delegserver.storage.sql.table.DSOA2ClientTable;

public class DSOA2ClientSQLStoreProvider<V extends SQLClientStore> extends OA2ClientSQLStoreProvider<V> {

    public DSOA2ClientSQLStoreProvider(ConnectionPoolProvider<? extends ConnectionPool> cpp, String type, MapConverter converter, Provider<? extends Client> clientProvider) {
        super(cpp, type, converter, clientProvider);
    }
	
    @Override
    // Note we cannot prevent unchecked cast to V. Also suppresses warning about the cast in clientProvider
    @SuppressWarnings("unchecked")
    public V newInstance(Table table) {
        return (V) new SQLClientStore<>(getConnectionPool(), table, (Provider<DSOA2Client>) clientProvider, converter);
    }
    
    @Override
       public V get() {
        ClientStoreTable cst = new DSOA2ClientTable(
                   new DSOA2ClientKeys(),
                   getSchema(),
                   getPrefix(),
                   getTablename());
           return newInstance(cst);
       }
}
