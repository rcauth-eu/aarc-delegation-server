package eu.rcauth.delegserver.storage;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import net.sf.json.JSONObject;

public class DSOA2ClientConverter<V extends DSOA2Client> extends OA2ClientConverter<V> {

    public DSOA2ClientConverter(IdentifiableProvider<V> identifiableProvider) {
        this(new DSOA2ClientKeys(), identifiableProvider);
    }

    public DSOA2ClientConverter(SerializationKeys keys, IdentifiableProvider<V> identifiableProvider) {
        super(keys, identifiableProvider);
    }

    protected DSOA2ClientKeys getDSCK() {
        return (DSOA2ClientKeys) keys;
    }

    @Override
    public void toMap(V client, ConversionMap<String, Object> map) {
        super.toMap(client, map);

        map.put(getDSCK().description, client.getDescription());
    }


    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V client =  super.fromMap(map, v);

        client.setDescription( map.getString( getDSCK().description ) );

        return client;
    }

    @Override
    public V fromJSON(JSONObject json) {
        V v = super.fromJSON(json);
        v.setDescription(getJsonUtil().getJSONValueString(json, ((DSOA2ClientKeys)getCK2()).description()));

        return v;
    }

    @Override
    public void toJSON(V client, JSONObject json) {
        super.toJSON(client, json);

        if (client.getDescription() != null) {
            getJsonUtil().setJSONValue(json, ((DSOA2ClientKeys)getCK2()).description(), client.getDescription());
        }
    }
}
