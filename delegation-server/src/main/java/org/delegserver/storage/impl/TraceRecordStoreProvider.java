package org.delegserver.storage.impl;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.delegserver.storage.TraceRecordStore;

import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

public abstract class TraceRecordStoreProvider<T extends TraceRecordStore> extends MultiTypeProvider<T> {

    public TraceRecordStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target) {
    	super(config, disableDefaultStore, logger, type, target);
    }
	
}
