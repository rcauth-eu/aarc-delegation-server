package eu.rcauth.delegserver.storage;

import eu.rcauth.delegserver.oauth2.DSOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;

import net.sf.json.JSONObject;
import java.util.Map;

public class DSOA2TConverter<V extends DSOA2ServiceTransaction> extends OA2TConverter<V> {

    public DSOA2TConverter(DSOA2TransactionKeys keys, IdentifiableProvider<V> identifiableProvider, TokenForge tokenForge, ClientStore<? extends Client> cs) {
        super(keys, identifiableProvider, tokenForge, cs);
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V st = super.fromMap(map, v);

        DSOA2TransactionKeys tck = (DSOA2TransactionKeys) getTCK();

        String jsonClaims = map.getString(tck.claims);
        if ( jsonClaims != null && !jsonClaims.isEmpty() )
            st.setClaims( JSONObject.fromObject(jsonClaims) );

        String jsonAttributes = map.getString(tck.user_attributes);
        if ( jsonAttributes != null && ! jsonAttributes.isEmpty() ) {
            // Unfortunately JSONObject doesn't provide an easy way to convert to a Map although it actually is one
            @SuppressWarnings("unchecked")
            Map<String, Object> attrMap = JSONObject.fromObject(jsonAttributes);
            st.setUserAttributes( attrMap);
        }

        st.setCnHash( map.getString(tck.cn_hash) );

        String seqNrString = map.getString(tck.sequence_nr);
        try {
            st.setSequenceNr(Integer.parseUnsignedInt(seqNrString));
        } catch(NumberFormatException e)    {
            st.setSequenceNr(-1);
        }

        return st;
    }


    @Override
    public void toMap(V t, ConversionMap<String, Object> map) {
        super.toMap(t, map);

        DSOA2TransactionKeys tck = (DSOA2TransactionKeys) getTCK();

        JSONObject claims = t.getClaims();
        if ( claims != null ) {
            // Note: t.getClaims returns a JSONObject, need to put it as a
            // String in the map, or fromMap() above cannot parse it.
            map.put( tck.claims , claims.toString() );
        }

        Map<String, Object> userAttributes = t.getUserAttributes();
        if ( userAttributes != null ) {
            // Note: t.getAttributes returns a Map<String, Object>.
            // We first must convert that into a JSONObject and then convert
            // that into String to put in the map as value, or fromMap() above
            // cannot parse it.
            map.put( tck.user_attributes , JSONObject.fromObject(userAttributes).toString() );
        }

        String cnHash = t.getCnHash();
        if ( cnHash != null && ! cnHash.isEmpty() ) {
            map.put( tck.cn_hash , cnHash );
        }

        int seqNumber = t.getSequenceNr();
        if (seqNumber>=0) {
            map.put( tck.sequence_nr , seqNumber);
        }

    }

}
