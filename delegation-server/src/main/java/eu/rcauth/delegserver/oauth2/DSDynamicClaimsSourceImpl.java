package eu.rcauth.delegserver.oauth2;

import java.util.Map;
import java.util.Collection;
import java.util.HashSet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;

import edu.uiuc.ncsa.security.servlet.PresentableState;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizationServer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAuthorizationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2DiscoveryServlet;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;
import eu.rcauth.delegserver.oauth2.servlet.DSOA2AuthorizationServer;


/**
 * Custom ClaimsSourceImpl that adds the list of supported claims into the UserInfo.
 * This is done in {@link OA2DiscoveryServlet}#setValues(HttpServletRequest, JSONObject)
 * using oa2SE.getClaimSource().getClaims(). Hence we override here {@link #getClaims()}.
 * <br>
 * For the ID token, all the (extra) claims are already put in
 * the transaction by
 * {@link DSOA2AuthorizationServer}#generateClaims(AuthorizedState)
 * in
 * {@link DSOA2AuthorizationServer#prepare(PresentableState)}
 * Doing this instead by overriding process here would not help as it would only
 * run after the consent page with the claims is already shown (in
 * {@link OA2AuthorizationServer}#createRedirect(HttpServletRequest, HttpServletResponse, ServiceTransaction)
 * called from {@link AbstractAuthorizationServlet}#doIt(HttpServletRequest, HttpServletResponse)
 * with {@link AbstractAuthorizationServlet#AUTHORIZATION_ACTION_OK}).
 * <br>
 * Additionally it is only invoked if both {@link #isEnabled()} and
 * {@link #isRunAtAuthorization()} are true
 * ({@link BasicClaimsSourceImpl#isEnabled()} returns true if it has a valid
 * {@link ClaimSourceConfiguration}, which additionally is set to enabled, see
 * also the constructor).
 *
 * @author "Tamás Balogh"
 * @author "Mischa Sall&eacute;"
 *
 */
public class DSDynamicClaimsSourceImpl extends BasicClaimsSourceImpl    {

    /**
     * Constructor for a DSDynamicClaimsSourceImpl.
     * We disable it for creating claims in the ID token, as that is handle
     * elsewhere, by setting the configuration to null.
     */
    public DSDynamicClaimsSourceImpl() {
        /* We currently don't need this ClaimsSourceImpl. */
        this.setConfiguration(null);
/*      ClaimSourceConfiguration claimSourceConfiguration = new ClaimSourceConfiguration();
        claimSourceConfiguration.setEnabled(true);
        this.setConfiguration(claimSourceConfiguration);*/
    }

    /**
     * Return a flattened list of all the claims in all the scopes as configured
     * in the &lt;scopes&gt; node. Used in the {@link OA2DiscoveryServlet}.
     * @return complete set of configured claims
     */
    @Override
    public Collection<String> getClaims() {
        HashSet<String> claims = new HashSet<>();
        DSOA2ServiceEnvironment dsoa2se = (DSOA2ServiceEnvironment)getOa2SE();
        Map<String,Map<String,String>> scopesMap = dsoa2se.getScopesMap();

        // iterate of scope -> claimsMap
        for (Map.Entry<String,Map<String,String>> entry : scopesMap.entrySet()) {
            Map<String,String> claimsMap = entry.getValue();

            // some scopes can be without claims
            if (claimsMap == null)  {
                dsoa2se.info("Skipping scope with no claims: "+entry.getKey());
            } else {
//              dsoa2se.debug("Adding claims from scope: "+entry.getKey());
                claims.addAll(claimsMap.keySet());
            }
        }

        return claims;
    }
}
