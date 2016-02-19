package org.delegserver.storage.sql.table;

import org.delegserver.storage.DNRecordKeys;

import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.CHAR;

public class DNRecordTable extends Table {

    public DNRecordTable(DNRecordKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }
	
    @Override
    public void createColumnDescriptors() {
    	super.createColumnDescriptors();
    	DNRecordKeys x =  (DNRecordKeys) keys;
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.dn_hash(), CHAR));	
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.attribute_hash(), CHAR));
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.attribute_list(), CHAR));	
    }
    
}
