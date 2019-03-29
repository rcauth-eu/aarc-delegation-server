package eu.rcauth.delegserver.storage;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import net.sf.json.JSONArray;

import java.util.ArrayList;

public class TraceRecordConverter<V extends TraceRecord> extends MapConverter<V> {

    public TraceRecordConverter(IdentifiableProvider<V> identifiableProvider) {
        super(new TraceRecordKeys(), identifiableProvider);
    }

    public TraceRecordConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    private TraceRecordKeys getTRKeys() {
        return (TraceRecordKeys) keys;
    }

    @Override
    @SuppressWarnings("unchecked") // for toCollection
    public V fromMap(ConversionMap<String, Object> map, V v) {
        v = super.fromMap(map, v);

        v.setCnHash( map.getString( getTRKeys().cn_hash()) );
        v.setSequenceNr( parseInt(map, getTRKeys().sequence_nr()) );

        v.setAttrHash( map.getString( getTRKeys().attribute_hash()) );
        v.setAttrSalt( map.getString( getTRKeys().attribute_salt() ) );
        // Note: map.getString() returns a String representation of a JSONArray,
        // so first convert into a JSONArray and then convert that into a List
        JSONArray jsonArray = JSONArray.fromObject(map.getString(getTRKeys().attribute_names()));
        // Unfortunately JSONArray does not understand generics/templating
        // hence this gives an unchecked cast warning.
        v.setAttrNames( new ArrayList<String>(JSONArray.toCollection(jsonArray, String.class)) );
        return v;
    }

    @Override
    public void toMap(V v, ConversionMap<String, Object> map) {
        super.toMap(v, map);
        map.put( getTRKeys().cn_hash() , v.getCnHash());
        map.put( getTRKeys().sequence_nr , v.getSequenceNr());

        map.put( getTRKeys().attribute_hash() , v.getAttrHash());
        map.put( getTRKeys().attribute_salt() , v.getAttrSalt());

        // Note: need to convert the String List in getAttrNames() into a String representation of a JSONArray
        map.put( getTRKeys().attribute_names() , JSONArray.fromObject(v.getAttrNames()).toString() );
    }


    private int parseInt(ConversionMap<String, Object> map, String key) {
        Object obj = map.get(key);
        if(obj instanceof Integer){
            return (Integer) obj;
        }
        return Integer.parseUnsignedInt(obj.toString());
    }

}
