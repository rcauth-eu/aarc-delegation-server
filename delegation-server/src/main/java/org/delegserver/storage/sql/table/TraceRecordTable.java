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
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.sequence_nr(), SMALLINT, false, true));
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.attribute_hash(), CHAR));
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.attribute_salt(), CHAR));
    	getColumnDescriptor().add(new ColumnDescriptorEntry(x.attribute_names(), CHAR));
    }
    
    public String createMultiSelectStatement(int count){
        
    	String select =  "SELECT * FROM " + getFQTablename() + " WHERE ";
    	
    	if ( count > 0 ) {
    		select += getPrimaryKeyColumnName() + " =?";
    	}
    	
        for ( int i=1 ; i<count ; i++ ) {
        	select += "OR " + getPrimaryKeyColumnName() + " =?";
        }
        
        select += " ORDER BY last_seen DESC";
        
        return select;
    }    
    
	@Override
	public String createUpdateStatement() {
        String update = "UPDATE " + getFQTablename() + " SET ";
        boolean isFirst = true;
        for (ColumnDescriptorEntry cde : getColumnDescriptor()) {
            
        	if (!cde.isPrimaryKey()) {
        		update = update + (isFirst ? "" : ", ") + cde.getName() + "=?";
                if (isFirst) {
                    isFirst = false;
                }   
            }        	
        }

        update += ", last_seen=CURRENT_TIMESTAMP";
        
        TraceRecordKeys x =  (TraceRecordKeys) keys;
        String where = " WHERE " + x.cn_hash() + "=?" + " AND " + x.sequence_nr() + "=?";
        
        // finally, add in the primary key.
        return update + where;
	}

    public String createMultiKeySelectStatement(){
        TraceRecordKeys x =  (TraceRecordKeys) keys;
        return "SELECT * from " + getFQTablename() + " where " + x.cn_hash() + "=?" + " AND " + x.sequence_nr() + "=?";
    }    
    
    @Override
    public String createInsertStatement() {
        String out = "insert into " + getFQTablename() + "(" + createRegisterStatement() + ", last_seen" + ") values (" ;
        String qmarks = "";
        for (int i = 0; i < getColumnDescriptor().size(); i++) {
            qmarks = qmarks + "?" + (i + 1 == getColumnDescriptor().size() ? "" : ", ");
        }
        qmarks += ",CURRENT_TIMESTAMP";
        
        out = out + qmarks + ")";
        return out;
    }
    
}
