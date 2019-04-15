package eu.rcauth.delegserver.storage.sql.table;

import eu.rcauth.delegserver.storage.TraceRecordKeys;

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
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.sequence_nr(), SMALLINT, false, true));
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.attribute_hash(), CHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.attribute_salt(), CHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.attribute_names(), CHAR));
    }

    public String createMultiSelectStatement(int count){

        StringBuilder select = new StringBuilder("SELECT * FROM " + getFQTablename() + " WHERE ");

        if ( count > 0 )
            select.append(getPrimaryKeyColumnName()).append(" =?");

        for ( int i=1 ; i<count ; i++ ) {
            select.append("OR ").append(getPrimaryKeyColumnName()).append(" =?");
        }

        select.append(" ORDER BY last_seen DESC");

        return select.toString();
    }

    @Override
    public String createUpdateStatement() {
        StringBuilder update = new StringBuilder("UPDATE " + getFQTablename() + " SET ");
        boolean isFirst = true;
        for (ColumnDescriptorEntry cde : getColumnDescriptor()) {

            if (!cde.isPrimaryKey()) {
                update.append(isFirst ? "" : ", ").append(cde.getName()).append("=?");
                if (isFirst)
                    isFirst = false;
            }
        }

        update.append(", last_seen=CURRENT_TIMESTAMP");

        TraceRecordKeys x =  (TraceRecordKeys) keys;
        update.append(" WHERE ").append(x.cn_hash()).append("=?").append(" AND ").append(x.sequence_nr()).append("=?");

        // finally, add in the primary key.
        return update.toString();
    }

    public String createMultiKeySelectStatement(){
        TraceRecordKeys x =  (TraceRecordKeys) keys;
        return "SELECT * from " + getFQTablename() + " where " + x.cn_hash() + "=?" + " AND " + x.sequence_nr() + "=?";
    }

    @Override
    public String createInsertStatement() {
        StringBuilder out = new StringBuilder("insert into " + getFQTablename() + "(" + createRegisterStatement() + ", last_seen" + ") values (" );
        for (int i = 0; i < getColumnDescriptor().size(); i++) {
            out.append("?").append(i + 1 == getColumnDescriptor().size() ? "" : ", ");
        }
        out.append(",CURRENT_TIMESTAMP)");

        return out.toString();
    }

}
