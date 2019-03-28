package org.delegserver.storage.sql.table;

import org.delegserver.storage.DSOA2ClientKeys;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientTable;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

import static java.sql.Types.LONGVARCHAR;

public class DSOA2ClientTable extends OA2ClientTable {

    public DSOA2ClientTable(DSOA2ClientKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        DSOA2ClientKeys k = (DSOA2ClientKeys)keys;
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.description(), LONGVARCHAR));
    }
	
}
