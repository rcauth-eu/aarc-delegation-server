package org.delegserver.storage.sql;

import javax.inject.Provider;

import org.delegserver.storage.TraceRecord;
import org.delegserver.storage.TraceRecordStore;

import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

public class SQLTraceRecordStore extends ExtendedSQLStore<TraceRecord> implements TraceRecordStore<TraceRecord> {

	public static final String DEFAULT_TABLENAME = "trace_records";
	
    public SQLTraceRecordStore(ConnectionPool connectionPool,
            Table table,
            Provider<TraceRecord> identifiableProvider,
            MapConverter converter) {
    	super(connectionPool, table, identifiableProvider, converter);
    }
	
}
