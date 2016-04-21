package org.delegserver.storage;

import org.delegserver.oauth2.util.JSONConverter;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

public class TraceRecordConverter<V extends TraceRecord> extends MapConverter<V> {

    public TraceRecordConverter(IdentifiableProvider<V> identifiableProvider) {
        super(new TraceRecordKeys(), identifiableProvider);
    }
	
	public TraceRecordConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
		super(keys, provider);
	}
	
	private TraceRecordKeys getKeys() {
		return (TraceRecordKeys) keys;
	}
	
	@Override
	public V fromMap(ConversionMap<String, Object> map, V v) {
		v = super.fromMap(map, v);
		
		v.setCnHash( map.getString( getKeys().cn_hash()) );
		v.setSequenceNr( parseInt(map, getKeys().sequence_nr()) );
		
		v.setAttrHash( map.getString( getKeys().attribute_hash()) );
		v.setAttrNames( JSONConverter.fromJSONArray( map.getString(getKeys().attribute_names()) ) );
		return v;
	}
	
	@Override
	public void toMap(V v, ConversionMap<String, Object> map) {
		super.toMap(v, map);
		map.put( getKeys().cn_hash() , v.getCnHash());
		map.put( getKeys().sequence_nr , v.getSequenceNr());
		
		map.put( getKeys().attribute_hash() , v.getAttrHash());
		map.put( getKeys().attribute_salt() , v.getAttrSalt());
		
		map.put( getKeys().attribute_names() , JSONConverter.toJSONArray( v.getAttrNames() ).toJSONString() );
	}

	
	private int parseInt(ConversionMap<String, Object> map, String key) {
        Object obj = map.get(key);
        if(obj instanceof Integer){
            return (Integer) obj;
        } 
        return Integer.parseUnsignedInt(obj.toString());		
	}
	
}
