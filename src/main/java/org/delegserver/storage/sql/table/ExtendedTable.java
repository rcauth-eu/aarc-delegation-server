package org.delegserver.storage.sql.table;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

public class ExtendedTable extends Table {

	public ExtendedTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
		super(keys, schema, tablenamePrefix, tablename);
	}
	
    public String createMultiSelectStatement(int count){
        
    	String select =  "SELECT * FROM " + getFQTablename() + " WHERE ";
    	
    	if ( count > 0 ) {
    		select += getPrimaryKeyColumnName() + " =?";
    	}
    	
        for ( int i=1 ; i<count ; i++ ) {
        	select += "OR " + getPrimaryKeyColumnName() + " =?";
        }
        
        return select;
    }	

}
