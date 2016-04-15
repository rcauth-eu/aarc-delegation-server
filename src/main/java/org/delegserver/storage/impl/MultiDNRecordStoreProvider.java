package org.delegserver.storage.impl;

import java.util.List;

import org.apache.commons.configuration.tree.ConfigurationNode;
import org.delegserver.storage.TraceRecord;
import org.delegserver.storage.DNRecordStore;

import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

public class MultiDNRecordStoreProvider<T extends TraceRecord> extends DNRecordStoreProvider<DNRecordStore<T>> {

    public MultiDNRecordStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target) {
    	super(config, disableDefaultStore, logger, type, target);
    }

	@Override
	public DNRecordStore<T> getDefaultStore() {
		throw new NotImplementedException("DNStoreProvider does not have a default store. Yet.");
	}
	
	/*
	@Override
	public DNRecordStore<T> get() {
		DNRecordStore<T> t =  super.get();
		
		List kidList = getConfig().getChildren();
        for (int i = 0; i < kidList.size(); i++) {
            ConfigurationNode foo = (ConfigurationNode) kidList.get(i);
            
            System.out.println( "===============================================" );
            System.out.println( "Looking for " + foo.getName() );
            DNRecordStore<T> gotOne = fireComponentFound(new CfgEvent(this, foo));
            if (gotOne != null) {
            	System.out.println( "Got it! " + gotOne.getClass() );
            }
            System.out.println( "===============================================" );
        }
		
		return t;
	}
	*/
	
}
