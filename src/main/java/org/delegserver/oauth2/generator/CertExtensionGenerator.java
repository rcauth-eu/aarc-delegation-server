package org.delegserver.oauth2.generator;

import java.util.List;
import java.util.Map;

import edu.uiuc.ncsa.security.core.Logable;

public class CertExtensionGenerator {

	protected static String EMAIL_EXTENSION = "email";
	
	protected Map<String, String> extensionSources;

	protected Logable logger;
	
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
	 * The behavior of this method is configurable through the '\<extensions\>' section
	 * of the configuration file.
	 * 
	 * @param trans The current service transaction
	 * @return The extensions that will be requested
	 */
	public String getCertificateExtensions(Map<String, Object> attributeMap) {
		
		// collection of info extensions separated with comma (',')
		String infoExtensions = "";
		// collection of email extension separated with whitespace (' ')
		String emailExtension = "";

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
					if ( extName.equals(EMAIL_EXTENSION) ) {
						emailExtension +=  (emailExtension.isEmpty()) ?  extName + "=" + ((String) ext) : " " + extName + "=" + ((String) ext);						 
					} else {
						infoExtensions +=  (infoExtensions.isEmpty()) ?  extName + "=" + ((String) ext) : "," + extName + "=" + ((String) ext);
					}
					
					i++;
					
				} else if ( ext instanceof List ) {
					// the extension value can be multi-valued. 
					List<String> attrList = ((List<String>)ext);
					for ( String v : attrList ) {
						
						// distinguish between EMAIL and INFO extensions
						if ( extName.equals(EMAIL_EXTENSION) ) {
							emailExtension +=  (emailExtension.isEmpty()) ?  extName + "=" + v : " " + extName + "=" + v;						 
						} else {
							infoExtensions +=  (infoExtensions.isEmpty()) ?  extName + "=" + v : "," + extName + "=" + v;
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
		String extensions = "";
		if ( ! emailExtension.isEmpty() ) {
			extensions += emailExtension;
		}
		if ( ! infoExtensions.isEmpty() ) {
			extensions += " info:" + infoExtensions; 
		}
		
		return extensions;
	}
	

	
}
