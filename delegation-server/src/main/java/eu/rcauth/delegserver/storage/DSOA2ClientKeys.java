package eu.rcauth.delegserver.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;

public class DSOA2ClientKeys extends OA2ClientKeys {

    String description = "description";

    public String description(String... x) {
        if (0 < x.length) description = x[0];
        return description;
    }
	
}
