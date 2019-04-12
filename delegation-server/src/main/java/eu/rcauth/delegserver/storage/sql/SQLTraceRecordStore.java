package eu.rcauth.delegserver.storage.sql;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.inject.Provider;

import eu.rcauth.delegserver.storage.TraceRecord;
import eu.rcauth.delegserver.storage.TraceRecordStore;
import eu.rcauth.delegserver.storage.sql.table.TraceRecordTable;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

public class SQLTraceRecordStore extends SQLStore<TraceRecord> implements TraceRecordStore<TraceRecord> {

	public static final String DEFAULT_TABLENAME = "trace_records";
	
    public SQLTraceRecordStore(ConnectionPool connectionPool,
            Table table,
            Provider<TraceRecord> identifiableProvider,
            MapConverter<TraceRecord> converter) {
    	super(connectionPool, table, identifiableProvider, converter);
    }
	
	public int getNextSequenceNumber(Identifier identifier) {
		
		List<Identifier> ids = new ArrayList<>();
		ids.add(identifier);
		
		List<TraceRecord> traceRecords = getAll(ids);
		
		if ( traceRecords != null ) {
			return traceRecords.size();
		} else {
			return 0;
		}
	}
	
	public List<TraceRecord> getAll(List<Identifier> ids) {
		
        Connection c = getConnection();
        List<TraceRecord> resultSet = new ArrayList<>();
        try {
        	
        	if ( !(getTable() instanceof TraceRecordTable) ) {
        		throw new NFWException("The table implementation " + getTable().getFQTablename() + " + does not extend TraceRecordTable!");
        	}
        	TraceRecordTable table = (TraceRecordTable) getTable();

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
            	
            	TraceRecord t = create();
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
	
	@Override
	public void save(TraceRecord value) {
        if (containsKey(value)) {
            update(value);
        } else {
            register(value);
        }
    
	}
	
	@Override
	public void update(TraceRecord value) {
		
        if (!containsValue(value)) {
            throw new GeneralException("Error: cannot update non-existent entry for\"" +
                    value.getIdentifierString() + "\". Register it first or call save.");
        }
        Connection c = getConnection();
        try {

            PreparedStatement stmt = c.prepareStatement(getTable().createUpdateStatement());
            ColumnMap map = depopulate(value);
            int i = 1;
            for (ColumnDescriptorEntry cde : getTable().getColumnDescriptor()) {
                // now we loop through the table and set each and every one of these
                if (!cde.isPrimaryKey()) {
                    Object obj = map.get(cde.getName());
                    // Dates confuse setObject, so turn it into an SQL Timestamp object.
                    if (obj instanceof Date) {
                        obj = new Timestamp(((Date) obj).getTime());
                    }
                    if (obj instanceof BasicIdentifier) {
                        stmt.setString(i++, obj.toString());
                    } else {
                        stmt.setObject(i++, obj);
                    }
                }
            }

            // now set the two primary keys: cnHash and sequence_nr
            stmt.setString(i++, value.getCnHash());
            stmt.setInt(i, value.getSequenceNr());
            
            stmt.executeUpdate();
            stmt.close();

        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error updating approval with identifier = \"" + value.getIdentifierString(), e);
        } finally {
            releaseConnection(c);
        }
		
	}
	
	@Override
	public boolean containsKey(Object key) {
		if ( !(key instanceof TraceRecord) ) {
			return super.containsKey(key);
		}
		
		TraceRecord value = (TraceRecord) key;
		
        Connection c = getConnection();
        boolean rc = false;
        try {
            PreparedStatement stmt = c.prepareStatement( ((TraceRecordTable)getTable()).createMultiKeySelectStatement() );
            
            stmt.setString(1, value.getCnHash());
            stmt.setInt(2, value.getSequenceNr());
            
            stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content of x as per JDBC spec.
            ResultSet rs = stmt.getResultSet();
            rc = rs.next();
            rs.close();
            stmt.close();

        } catch (SQLException e) {
            destroyConnection(c);
            e.printStackTrace();
        } finally {
            releaseConnection(c);
        }
        return rc;		
	}
    
}
