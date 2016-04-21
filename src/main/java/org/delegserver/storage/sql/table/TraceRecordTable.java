package org.delegserver.storage.sql.table;

import org.delegserver.storage.TraceRecordKeys;

import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.CHAR;
import static java.sql.Types.SMALLINT;

public class TraceRecordTable extends Table {

    public TraceRecordTable(TraceRecordKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }
	
    @Override
    public void createColumnDescriptors() {
    	super.createColumnDescriptors();
    	TraceRecordKeys x =  (TraceRecordKeys) keys;
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.cn_hash(), CHAR, false, true));
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.sequence_nr(), SMALLINT));
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.attribute_hash(), CHAR));
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.attribute_salt(), CHAR));
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.attribute_names(), CHAR));
    }
    
}
