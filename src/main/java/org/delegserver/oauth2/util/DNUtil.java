package org.delegserver.oauth2.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;

public class DNUtil {

	public static final String DN_TEMPLATE = "/O=Grid/OU=GlobusTest/CN="; 
	
	public static String getUserDN(OA2ServiceTransaction transaction) {
		return DN_TEMPLATE + transaction.getUsername();
	}
	
}
