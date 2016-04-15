package org.delegserver.storage.impl;

import javax.inject.Provider;

import org.delegserver.storage.TraceRecord;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;

public class DNRecordProvider extends IdentifiableProviderImpl<TraceRecord> {

	public DNRecordProvider(Provider<Identifier> idProvider) {
		super(idProvider);
	}

	@Override
	public TraceRecord get(boolean createNewIdentifier) {
		return new TraceRecord(createNewId(createNewIdentifier));
	}
	
}
