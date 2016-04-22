package org.delegserver.storage;

import java.util.List;
import java.util.Set;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;

public interface TraceRecordStore<V extends TraceRecord> extends Store<V> {

	public Set<V> getAll(List<Identifier> identifiers);
	
}
