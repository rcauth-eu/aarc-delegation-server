package org.delegserver.storage.sql;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;


import javax.inject.Provider;

import org.delegserver.storage.sql.table.ExtendedTable;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

public abstract class ExtendedSQLStore<V extends Identifiable> extends SQLStore<V> {

	public ExtendedSQLStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider,
			MapConverter converter) {
		super(connectionPool,table,identifiableProvider,converter);
	}

	public List<V> getAll(List<Identifier> ids) {
		
        Connection c = getConnection();
        List<V> resultSet = new ArrayList<V>(); 
        try {
        	
        	if ( !(getTable() instanceof ExtendedTable) ) {
        		throw new NFWException("The table implementation " + getTable().getFQTablename() + " + does not extend ExtendedTable!");
        	}
        	ExtendedTable table = (ExtendedTable) getTable();

        	// construct statement using the ids provided 
            PreparedStatement stmt = c.prepareStatement(table.createMultiSelectStatement(ids.size()));
            for (int i=0 ; i<ids.size() ; i++) {
            	stmt.setString(i + 1, ids.get(i).toString() );
            }
            
            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            
            // iterate over result set
            while ( rs.next() ) {
            	ColumnMap map = rsToMap(rs);
            	
            	V t = create();
                populate(map, t);
                
                resultSet.add(t);
            }
            
            rs.close();
            stmt.close();

        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error getting objects from the provided ID set", e);
        } finally {
            releaseConnection(c);
        }
        
        if (  resultSet.isEmpty() ) {
        	return null;
        } 
        
        return resultSet;
	}
	
	
}
