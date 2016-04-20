package org.delegserver.storage;

import java.util.List;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

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
		v.setAttrNames( parseJSONArray(map, getKeys().attribute_names()) );
		return v;
	}
	
	@Override
	public void toMap(V v, ConversionMap<String, Object> map) {
		super.toMap(v, map);
		map.put( getKeys().cn_hash() , v.getCnHash());
		map.put( getKeys().sequence_nr , v.getSequenceNr());
		
		map.put( getKeys().attribute_hash() , v.getAttrHash());
		map.put( getKeys().attribute_salt() , v.getAttrSalt());
		
		JSONArray json = new JSONArray();
		for (String s : v.getAttrNames()) {
			json.add(s);
		}
		map.put( getKeys().attribute_names() , json.toJSONString());
	}

	
	private int parseInt(ConversionMap<String, Object> map, String key) {
        Object obj = map.get(key);
        if(obj instanceof Integer){
            return (Integer) obj;
        } 
        return Integer.parseUnsignedInt(obj.toString());		
	}
	
	private List<String> parseJSONArray(ConversionMap<String, Object> map, String key) {
		Object obj = map.get(key);
		JSONParser parser = new JSONParser(0);
		
		try {
			Object parsedObj = parser.parse(obj.toString());
			if (parsedObj instanceof JSONArray) {
				return (List<String>) parsedObj;
			} else {
				return null;
			}
		} catch (ParseException e) {
			throw new GeneralException("Cannot parse JSONArray from map with key : " + key);
		}
		
	}
}
