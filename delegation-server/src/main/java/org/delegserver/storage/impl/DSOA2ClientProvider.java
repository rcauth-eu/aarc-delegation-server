package org.delegserver.storage.impl;

import org.delegserver.storage.DSOA2Client;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ClientProvider;

public class DSOA2ClientProvider<V extends DSOA2Client> extends OA2ClientProvider<V> {

    public DSOA2ClientProvider(IdentifierProvider<Identifier> idProvider) {
        super(idProvider);
    }
    
    @Override
    protected V newClient(boolean createNewIdentifier) {
       return (V) new DSOA2Client(createNewId(createNewIdentifier));
    }

}
