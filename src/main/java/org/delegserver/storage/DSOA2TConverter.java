package org.delegserver.storage;

import java.util.Map;

import org.delegserver.oauth2.DSOA2ServiceTransaction;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

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
    		
    		try {
	    		
    			JSONParser parser = new JSONParser(0);
	    		Object obj = parser.parse(jsonClaims);
				
	    		if ( obj instanceof JSONObject ) {
	    			st.setClaims( ((Map) obj));
	    		}
    		
    		} catch (ParseException e) {
    			throw new GeneralException("Erro while parsing data record! Could not parse JSON claims: " + jsonClaims);
			}
    	}
    	
    	return st;
    }

    
    @Override
    public void toMap(V t, ConversionMap<String, Object> map) {
    	super.toMap(t, map);
    	
    	DSOA2TransactionKeys tck = (DSOA2TransactionKeys) getTCK();
 
    	if ( t.getClaims() != null ) {
    		JSONObject jsonClaim = new JSONObject(t.getClaims());
    		map.put( tck.claims , jsonClaim.toString());
    	}
    	
    }
    
}
