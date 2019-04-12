package eu.rcauth.delegserver.storage;

import java.net.URI;
import edu.uiuc.ncsa.security.core.Identifier;

public class TraceRecordIdentifier implements Identifier {

	String cnHash = null;
	
	public TraceRecordIdentifier(String cnHash) {
		this.cnHash = cnHash;
	}
	
	@Override
	public int compareTo(Object o) {
		
		if ( o instanceof TraceRecordIdentifier ) {
			return cnHash.compareTo( ((TraceRecordIdentifier)o).cnHash );
		} else {
			return cnHash.compareTo( o.toString() );
		}
	}

	@Override
	public URI getUri() {
		return null;
	}
	
	@Override
	public String toString() {
		return cnHash;
	}

	/* Override these two methods so that we can use this object as the
	 * key in a hash lookup table
	 */
	
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof TraceRecordIdentifier)
            return cnHash.equals(obj.toString());
		else
			return false;
	}

	@Override
	public int hashCode() {
		return cnHash.hashCode();
	}
	
}
