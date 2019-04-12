package eu.rcauth.delegserver.storage.impl;

import eu.rcauth.delegserver.storage.DSOA2Client;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientProvider;

public class DSOA2ClientProvider<V extends DSOA2Client> extends OA2ClientProvider<V> {

    public DSOA2ClientProvider(IdentifierProvider<Identifier> idProvider) {
        super(idProvider);
    }
    
    @Override
    // Note we cannot prevent unchecked cast to V
    @SuppressWarnings("unchecked")
    protected V newClient(boolean createNewIdentifier) {
       return (V) new DSOA2Client(createNewId(createNewIdentifier));
    }

}
