package org.delegserver.oauth2.servlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.UserInfoServlet;

public class DSUserInfoServlet extends UserInfoServlet {

	@Override
	protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
	
		response.setCharacterEncoding("UTF-8");
		
		super.doIt(request, response);
	}
	
	
	
}
