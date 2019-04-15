package eu.rcauth.delegserver.storage.sql.table;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionTable;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

import java.sql.Types;

import eu.rcauth.delegserver.storage.DSOA2TransactionKeys;

public class DSOA2TransactionTable extends OA2TransactionTable {

    public DSOA2TransactionTable(OA2TransactionKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry( ((DSOA2TransactionKeys)getOA2Keys()).claims(),
                                                             Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry( ((DSOA2TransactionKeys)getOA2Keys()).user_attributes(),
                                                             Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry( ((DSOA2TransactionKeys)getOA2Keys()).trace_record() ,
                                                             Types.LONGVARCHAR));
    }
}
