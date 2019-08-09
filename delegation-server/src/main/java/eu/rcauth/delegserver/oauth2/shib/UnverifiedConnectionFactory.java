package eu.rcauth.delegserver.oauth2.shib;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;

import edu.uiuc.ncsa.security.util.ssl.MyTrustManager;

/**
 * The motivation for this class is to be able to create https connections to 'localhost'
 * when 'localhost' is not explicitly listed in the server HttpsURLConnection certificate
 * as an altSubjectName.
 *
 * @author "Tamás Balogh"
 *
 */
public class UnverifiedConnectionFactory {

    // Special HostnameVerifier that only checked the source hostname to be 'localhost'
    // and accepts any hostname found in the server credentials.
    public class DSHostnameVerifier implements HostnameVerifier {

        @Override
        public boolean verify(String hostname, SSLSession session) {
            return hostname.equals("localhost");
        }

    }

    // Special TrustManager that will only verify the server certificate to be
    // valid against the trusted certificates in DEFAULT_TRUST_ROOT_PATH
    public class DSTrustManager extends MyTrustManager {

        public DSTrustManager() {
            super(null, (String)null);
            this.setTrustRootPath( this.DEFAULT_TRUST_ROOT_PATH );
        }

        @Override
        public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
            checkServerCertPath(certs);
        }
    }

    protected SSLContext sslContext = null;
    protected HostnameVerifier hostnameVerifier = null;

    public UnverifiedConnectionFactory() throws Throwable {

        try {
            // create custom ssl context with the DSTrustManager
            sslContext = SSLContext.getInstance("SSL");
            DSTrustManager mtm = new DSTrustManager();
            sslContext.init(null, new TrustManager[]{mtm}, new java.security.SecureRandom());

            // create custom hostname verifier
            hostnameVerifier = new DSHostnameVerifier();
        } catch (Exception e) {
            throw new Exception("Failed to initialize SSL Context for Shibboleth Assertion retrieval" ,e);
        }

    }

    /**
     * Convert a regular {@link HttpsURLConnection} into a less secure connection. What
     * this method does will disable the hostname verification of the server certificate
     * against the request url, but it will keep the certificate verification itself against
     * the trust anchors configured in /etc/grid-security/certificates. The motivation for this
     * method is to be able to create https connections to 'localhost' when 'localhost' is not
     * explicitly listed in the server HttpsURLConnection certificate as an altSubjectName.
     * <p>
     * ONLY USE THIS FOR CONNECTIONS MADE TO 'localhost' THAT YOU TRUST! DO NOT USE THIS FOR
     * ANY REMOTE CONNECTION BECAUSE IT WILL DISABLE HOSTNAME VERIFICATION!
     *
     * @param connection The connection you want to disable hostname verification on
     * @return the same connection, but with a different SSLContext and HostnameVerifier
     */
    public HttpsURLConnection getUnverifiedConnection(HttpsURLConnection connection) {
        // add our custom ssl context to the connection
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        // add null host verifier
        connection.setHostnameVerifier(hostnameVerifier);

        return connection;
    }

}
