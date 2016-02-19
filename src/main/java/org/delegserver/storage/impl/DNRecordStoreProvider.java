package org.delegserver.storage.impl;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.delegserver.storage.DNRecordStore;

import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

public abstract class DNRecordStoreProvider<T extends DNRecordStore> extends MultiTypeProvider<T> {

    public DNRecordStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target) {
    	super(config, disableDefaultStore, logger, type, target);
    }
	
}
