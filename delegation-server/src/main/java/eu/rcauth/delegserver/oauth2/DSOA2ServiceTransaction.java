package eu.rcauth.delegserver.oauth2;

import java.util.Map;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.core.Identifier;

/**
 * Custom Service Transaction extension containing:
 * <p>
 * {@link #userAttributes}: The set of attributes coming from the user IdP (mapped by the SP in front of
 * this server). This attribute set has to be part of a transaction so that it can be taken up
 * by subsequent /getcert request.
 * <p>
 * {@link #cnHash}: The key of the trace record entry linked with this transaction. This field is
 * used to link transactions with trace records. Note that a transaction only has a linked trace record
 * in case a /getcert call.
 * <p>
 * {@link #sequenceNr}: The sequence number for the cnHash.
 * <p>
 * {@link OA4MPServiceTransaction}#myproxyUsername: This is an already existing attribute that has been repurposed in this
 * implementation. It contains the user DN (O+CN) created for a user based on his attributes.
 *
 * @author "Tamás Balogh"
 *
 */
public class DSOA2ServiceTransaction extends OA2ServiceTransaction {

    public DSOA2ServiceTransaction(AuthorizationGrant ag) {
        super(ag);
    }

    public DSOA2ServiceTransaction(Identifier identifier) {
        super(identifier);
    }

    /* Support for saving user attributes released by the idp
     * into the transaction store
     */

    protected Map<String,Object> userAttributes;

    public Map<String, Object> getUserAttributes() {
        return userAttributes;
    }

    public void setUserAttributes(Map<String, Object> userAttributes) {
        this.userAttributes = userAttributes;
    }

    /* Support for saving the CN hash used by this transaction
     * This way we can link transactions with trace records.
     */

    protected String cnHash;

    public String getCnHash() {
        return cnHash;
    }

    public void setCnHash(String cnHash) {
        this.cnHash = cnHash;
    }

    protected int sequenceNr;

    public int getSequenceNr() {
        return sequenceNr;
    }

    public void setSequenceNr(int sequenceNr) {
        this.sequenceNr = sequenceNr;
    }
}
