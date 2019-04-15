package eu.rcauth.delegserver.oauth2.servlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import eu.rcauth.delegserver.storage.DSOA2Client;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2RegistrationServlet;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.servlet.PresentableState;

public class DSOA2RegistrationServlet extends OA2RegistrationServlet {

    public static final String CLIENT_DESCRIPTION = "clientDescription";

    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);

        HttpServletRequest request = state.getRequest();

        if (state.getState() == INITIAL_STATE) {
            request.setAttribute(CLIENT_DESCRIPTION, CLIENT_DESCRIPTION);
        }
    }

    @Override
    protected Client addNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        DSOA2Client client = (DSOA2Client) super.addNewClient(request, response);

        // TODO: set client description
        String desc =  getParameter(request, CLIENT_DESCRIPTION);

        System.out.println("Setting client desc to : " + desc);

        client.setDescription( desc );

        return client;
    }

}
