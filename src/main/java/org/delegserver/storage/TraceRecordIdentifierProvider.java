package org.delegserver.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;

public class TraceRecordIdentifierProvider extends IdentifierProvider {

	public TraceRecordIdentifierProvider() {
		super("");
	}
	
	@Override
	public Identifier get() {
		return (Identifier) new TraceRecordIdentifier(null);
	}
	
}
