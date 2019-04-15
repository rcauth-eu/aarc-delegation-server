package eu.rcauth.delegserver.storage;

import java.util.List;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;

public interface TraceRecordStore<V extends TraceRecord> extends Store<V> {

    List<V> getAll(List<Identifier> identifiers);

    int getNextSequenceNumber(Identifier identifier);
}
