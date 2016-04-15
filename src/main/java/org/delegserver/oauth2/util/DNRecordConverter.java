package org.delegserver.oauth2.util;

import org.delegserver.storage.TraceRecord;
import org.delegserver.storage.DNRecordKeys;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

public class DNRecordConverter<V extends TraceRecord> extends MapConverter<V> {

    public DNRecordConverter(IdentifiableProvider<V> identifiableProvider) {
        super(new DNRecordKeys(), identifiableProvider);
    }
	
	public DNRecordConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
		super(keys, provider);
	}
	
	private DNRecordKeys getKeys() {
		return (DNRecordKeys) keys;
	}
	
	@Override
	public V fromMap(ConversionMap<String, Object> map, V v) {
		v = super.fromMap(map, v);
		v.setDnHash( map.getString( getKeys().dn_hash()) );
		v.setAttrHash( map.getString( getKeys().attribute_hash()) );
		v.setAttrNames( map.getString( getKeys().attribute_list()) );
		return v;
	}
	
	@Override
	public void toMap(V v, ConversionMap<String, Object> map) {
		super.toMap(v, map);
		map.put( getKeys().dn_hash() , v.getDnHash());
		map.put( getKeys().attribute_hash() , v.getAttrHash());
		map.put( getKeys().attribute_list() , v.getAttrNames());
	}

}
