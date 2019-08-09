package eu.rcauth.delegserver.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;

public class DSOA2Client extends OA2Client {

    protected String description;

    public DSOA2Client(Identifier identifier) {
        super(identifier);
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public DSOA2Client clone() {
        DSOA2Client client = new DSOA2Client(getIdentifier());
        super.populateClone(client);
        client.setDescription( this.description );

        return client;
    }

    @Override
    public boolean equals(Object obj) {
        boolean superEquals = super.equals(obj);
        if ( !superEquals )
            return false;

        DSOA2Client c = (DSOA2Client) obj;
        return getDescription().equals(c.getDescription());

    }

}
