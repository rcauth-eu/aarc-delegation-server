package org.delegserver.storage.impl;

import javax.inject.Provider;

import org.delegserver.storage.DNRecord;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;

public class DNRecordProvider extends IdentifiableProviderImpl<DNRecord> {

	public DNRecordProvider(Provider<Identifier> idProvider) {
		super(idProvider);
	}

	@Override
	public DNRecord get(boolean createNewIdentifier) {
		return new DNRecord(createNewId(createNewIdentifier));
	}
	
}
