package eu.rcauth.delegserver.oauth2;

import java.util.Set;
import java.util.Map;
import java.util.Collection;
import java.util.HashSet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import net.sf.json.JSONObject;

// TODO add imports for javadoc

/**
 * Custom ClaimsSourceImpl that adds claims into UserInfo and IDToken.
 * <br>
 * TODO we need to decide whether we want to allow additional handlers, which
 * then also need additional configuration via a {@link ClaimSourceConfiguration}.
 * Currently, all the extra claims from the DS are already forwarded and put in
 * the transaction in
 * {@link eu.rcauth.delegationserver.server.servlet.DSOA2AuthorizationServer#prepare(PresentableState)}
 * by
 * {@link OA2ServiceTransaction#setClaims(JSONObject)}.
 * <br>
 * NOTE: this ClaimsSourceImpl is called 'on the way' back, when returning from
 * the mp-server to the (e.g. vo-portal) client. It is called by
 * {@link OA2ClaimsUtil#createBasicClaims(HttpServletRequest, OA2ServiceTransaction)},
 * called from
 * {@link DSOA2AuthorizationServer#createRedirect(HttpServletRequest, HttpServletResponse, ServiceTransaction)}.
 * It is only invoked if both {@link #isEnabled()} and
 * {@link #isRunAtAuthorization()} are true
 * ({@link BasicClaimsSourceImpl#isEnabled()} returns true if it has a valid
 * {@link ClaimSourceConfiguration}, which additionally is set to enabled, see
 * also the constructor).
 *
 * @author "Tamás Balogh"
 */
public class DSDynamicClaimsSourceImpl extends BasicClaimsSourceImpl    {

    /**
     * Constructor for a DSDynamicClaimsSourceImpl.
     * It needs to have a {@link ClaimSourceConfiguration} which is enabled.
     * See for example {@linkplain edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration}
     */
    public DSDynamicClaimsSourceImpl() {
        /* We currently don't need this ClaimsSourceImpl. */
        this.setConfiguration(null);
/*        ClaimSourceConfiguration claimSourceConfiguration = new ClaimSourceConfiguration();
        claimSourceConfiguration.setEnabled(true);
        this.setConfiguration(claimSourceConfiguration);*/
    }

    @Override
    // TODO Unclear what this does but it needs to be true or it's skipped in
    // edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil#createBasicClaims
    public boolean isRunAtAuthorization(){
        /* We currently don't use this ClaimsSourceImpl, so set to false. Also
         * need to have a enabled non-null configuration in order to run */
        return false;
/*        return true;*/
    }

    /**
     * Returns the {@link JSONObject} object passed to it completed with the claims saved by the
     * corresponding transaction.
     *
     * @param claims being returned to the client
     * @param transaction the current transaction record
     * @return The UserInfo completed with claims
     */
    @Override
    public JSONObject process(JSONObject claims, ServiceTransaction transaction) {

        //add the claims build based on the requested scopes into the userinfo reply

        //get claims previously extracted from the transaction
        DSOA2ServiceTransaction t = (DSOA2ServiceTransaction) transaction;
        JSONObject transClaims =  t.getClaims();

        // TODO check logic
        if ( transClaims != null ) {
            //some claims might already by set by now, so instead of overwriting them,
            //simple append the claims from the transaction.
            for ( String claimKey : (Set<String>)transClaims.keySet()) {
                claims.put(claimKey, transClaims.get(claimKey));
            }
        } else {
            //don't fail on empty claims
        }

        return claims;
    }

    /**
     * Return a flattened list of all the claims in all the scopes as configured
     * in the <scopes> node
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
