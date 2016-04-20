package org.delegserver.storage.sql;

import javax.inject.Provider;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.delegserver.oauth2.DSConfigTags;
import org.delegserver.storage.TraceRecord;
import org.delegserver.storage.TraceRecordKeys;
import org.delegserver.storage.sql.table.TraceRecordTable;

import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

public class SQLTraceRecordStoreProvider<V extends SQLTraceRecordStore> extends SQLStoreProvider<V> implements DSConfigTags {

	protected Provider<TraceRecord> dnRecordProvider;
	
    public SQLTraceRecordStoreProvider(
            ConfigurationNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp,
            String type,
            String target,
            String tablename,
            MapConverter converter,
            Provider<TraceRecord> dnrp) {
        super(config, cpp, type, target, tablename, converter);
        this.dnRecordProvider = dnrp;
    }

    public SQLTraceRecordStoreProvider(
            ConfigurationNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp,
            String type,
            MapConverter converter,
            Provider<TraceRecord> dnrp) {
        super(config, cpp, type, DSConfigTags.DN_RECORD_STORE, SQLTraceRecordStore.DEFAULT_TABLENAME, converter);
        this.dnRecordProvider = dnrp;
    }
     
    @Override
    public V newInstance(Table table) {
    	return (V) new SQLTraceRecordStore(getConnectionPool(), table, dnRecordProvider, converter);
    }
    
    @Override
    public V get() {
    	return newInstance( new TraceRecordTable( (TraceRecordKeys) converter.keys, getSchema(), getPrefix(), getTablename()));
    }
    
}
