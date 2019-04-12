package eu.rcauth.delegserver.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;

public class TraceRecordIdentifierProvider<V extends Identifier> extends IdentifierProvider<Identifier> {

	public TraceRecordIdentifierProvider() {
		super("");
	}
	
	@Override
	public Identifier get() {
		return new TraceRecordIdentifier(null);
	}
	

	
}
