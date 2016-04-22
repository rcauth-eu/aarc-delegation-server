package org.delegserver.storage;

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


}
