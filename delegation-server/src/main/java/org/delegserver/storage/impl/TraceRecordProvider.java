package org.delegserver.storage.impl;

import javax.inject.Provider;

import org.delegserver.storage.TraceRecord;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;

public class TraceRecordProvider extends IdentifiableProviderImpl<TraceRecord> {

	public TraceRecordProvider(Provider<Identifier> idProvider) {
		super(idProvider);
	}

	@Override
	public TraceRecord get(boolean createNewIdentifier) {
		return new TraceRecord(null);
	}
	
}
