package org.delegserver.storage.sql;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2SQLTransactionStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.DSSQLTransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.delegserver.storage.DSOA2TransactionKeys;
import org.delegserver.storage.sql.table.DSOA2TransactionTable;

import javax.inject.Provider;

public class DSOA2SQLTransactionStoreProvider<T extends DSSQLTransactionStore> extends OA2SQLTransactionStoreProvider<T> {

    public DSOA2SQLTransactionStoreProvider(ConfigurationNode config,
								            ConnectionPoolProvider<? extends ConnectionPool> cpp,
								            String type,
								            MultiDSClientStoreProvider clientStoreProvider,
								            Provider<? extends OA2ServiceTransaction> tp,
								            Provider<TokenForge> tfp,
								            MapConverter converter) {
    	
		   super(config, cpp, type, clientStoreProvider, tp, tfp, converter);
    }
			
	@Override
	public T get() {
		return newInstance(new DSOA2TransactionTable((DSOA2TransactionKeys)converter.keys, getSchema(), getPrefix(), getTablename()));
	}
				
}
