package org.delegserver.storage;

import java.util.Map;

import org.delegserver.oauth2.DSOA2ServiceTransaction;
import org.delegserver.oauth2.util.JSONConverter;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;

public class DSOA2TConverter<V extends DSOA2ServiceTransaction> extends OA2TConverter<V> {

    public DSOA2TConverter(DSOA2TransactionKeys keys, IdentifiableProvider<V> identifiableProvider, TokenForge tokenForge, ClientStore<? extends Client> cs) {
        super(keys, identifiableProvider, tokenForge, cs);
    }
	
    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
    	V st = super.fromMap(map, v);
    	
    	DSOA2TransactionKeys tck = (DSOA2TransactionKeys) getTCK();

    	String jsonClaims = map.getString(tck.claims);
    	if ( jsonClaims != null ) {
    		st.setClaims( (Map<String, Object>) JSONConverter.fromJSONObject(jsonClaims) );
    	}
    	
    	String jsonAttributes = map.getString(tck.user_attributes);
    	if ( jsonAttributes != null ) {
    		st.setUserAttributes( (Map<String, Object>) JSONConverter.fromJSONObject(jsonAttributes) );
    	}
    	
    	st.setTraceRecord( map.getString(tck.trace_record) );
    	
    	return st;
    }

    
    @Override
    public void toMap(V t, ConversionMap<String, Object> map) {
    	super.toMap(t, map);
    	
    	DSOA2TransactionKeys tck = (DSOA2TransactionKeys) getTCK();
 
    	if ( t.getClaims() != null ) {
    		map.put( tck.claims , JSONConverter.toJSONObject( t.getClaims() ).toJSONString() );
    	}
    	
    	if ( t.getUserAttributes() != null ) {
    		map.put( tck.user_attributes , JSONConverter.toJSONObject( t.getUserAttributes() ).toJSONString() );
    	}
    	
    	if ( t.getTraceRecord() != null && ! t.getTraceRecord().isEmpty() ) {
    		map.put( tck.trace_record , t.getTraceRecord() );
    	}
    	
    }
    
}
