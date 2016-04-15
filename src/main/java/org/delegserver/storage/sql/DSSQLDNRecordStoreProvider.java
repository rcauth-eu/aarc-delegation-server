package org.delegserver.storage.sql;

import javax.inject.Provider;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.delegserver.oauth2.DSConfigTags;
import org.delegserver.storage.TraceRecord;
import org.delegserver.storage.DNRecordKeys;
import org.delegserver.storage.sql.table.DNRecordTable;

import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

public class DSSQLDNRecordStoreProvider<V extends SQLDNRecordStore> extends SQLStoreProvider<V> implements DSConfigTags {

	protected Provider<TraceRecord> dnRecordProvider;
	
    public DSSQLDNRecordStoreProvider(
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

    public DSSQLDNRecordStoreProvider(
            ConfigurationNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp,
            String type,
            MapConverter converter,
            Provider<TraceRecord> dnrp) {
        super(config, cpp, type, DSConfigTags.DN_RECORD_STORE, SQLDNRecordStore.DEFAULT_TABLENAME, converter);
        this.dnRecordProvider = dnrp;
    }
     
    @Override
    public V newInstance(Table table) {
    	return (V) new SQLDNRecordStore(getConnectionPool(), table, dnRecordProvider, converter);
    }
    
    @Override
    public V get() {
    	return newInstance( new DNRecordTable( (DNRecordKeys) converter.keys, getSchema(), getPrefix(), getTablename()));
    }
    
}
