package org.delegserver.storage;

import edu.uiuc.ncsa.security.oauth_2_0.OA2ClientKeys;

public class DSOA2ClientKeys extends OA2ClientKeys {

    String description = "description";

    public String description(String... x) {
        if (0 < x.length) description = x[0];
        return description;
    }
	
}
