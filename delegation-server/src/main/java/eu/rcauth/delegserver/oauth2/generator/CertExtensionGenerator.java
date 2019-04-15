package eu.rcauth.delegserver.oauth2.generator;

import java.util.List;
import java.util.Map;

import edu.uiuc.ncsa.security.core.Logable;

public class CertExtensionGenerator {

    protected static final String EMAIL_EXTENSION = "email";

    protected final Map<String, String> extensionSources;

    protected final Logable logger;

    public CertExtensionGenerator(Map<String, String> extensionSources, Logable logger) {
        this.extensionSources = extensionSources;
        this.logger = logger;
    }

    /**
     * Returns addition information that has to be added as extension into the end entity
     * certificate. Extensions will be presented according to the following template:
     * <p>
     * email=m1 email=m2 info:key1=value1,key2=value2...
     * <p>
     * This collection of extensions has to be passed to the MyProxy Server appended to the
     *  USERNAME request parameter.
     * <p>
     * The behavior of this method is configurable through the {@code <extensions>} section
     * of the configuration file.
     *
     * @param attributeMap The attribute map containing user attributes
     * @return The extensions that will be requested
     */
    // Since ext can be either String or List<String> we cannot prevent an unchecked cast from ext to List<String>
    @SuppressWarnings("unchecked")
    public String getCertificateExtensions(Map<String, Object> attributeMap) {

        // collection of info extensions separated with comma (',')
        StringBuilder infoExtensions = new StringBuilder();
        // collection of email extension separated with whitespace (' ')
        StringBuilder emailExtension = new StringBuilder();

        logger.debug("GENERATING CERTIFICATE EXTENSIONS");

        // get extension names from the configuration
        for (String extName : extensionSources.keySet()) {

            // get the extension value based on the provided source
            Object ext = attributeMap.get( extensionSources.get(extName) );

            if ( ext == null ) {
                logger.warn("Certificate Extension " + extensionSources.get(extName) + " not found! Ignoring...");
            } else {
                logger.debug("	- Processing extension '" + extName + "' from source '" + extensionSources.get(extName) + "'");

                int i=0;

                if ( ext instanceof String ) {
                    // single valued extension

                    // distinguish between EMAIL and INFO extensions
                    if ( extName.equals(EMAIL_EXTENSION) )
                        emailExtension.append((emailExtension.length() == 0) ? extName + "=" + ext : " " + extName + "=" + ext);
                    else
                        infoExtensions.append((infoExtensions.length() == 0) ? extName + "=" + ext : "," + extName + "=" + ext);
                    i++;
                } else if ( ext instanceof List ) {
                    // the extension value can be multi-valued.
                    List<String> attrList = ((List<String>)ext);
                    for ( String v : attrList ) {

                        // distinguish between EMAIL and INFO extensions
                        if ( extName.equals(EMAIL_EXTENSION) ) {
                            emailExtension.append((emailExtension.length() == 0) ? extName + "=" + v : " " + extName + "=" + v);
                        } else {
                            infoExtensions.append((infoExtensions.length() == 0) ? extName + "=" + v : "," + extName + "=" + v);
                        }

                        i++;
                    }
                } else {
                    logger.error("Unexpected instance for attribute " + extName +". Was expecting either String or List<String>");
                    return null;
                }

                logger.debug("	- Added " + i + " extensions with name '" + extName + "'");

            }
        }

        // combine the extensions into a single line
        if (infoExtensions.length() > 0)
            emailExtension.append(" info:").append(infoExtensions.toString());

        return emailExtension.toString();
    }

}
