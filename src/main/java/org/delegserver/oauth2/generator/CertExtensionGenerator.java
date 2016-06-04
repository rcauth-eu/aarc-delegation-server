package org.delegserver.oauth2.generator;

import java.util.List;
import java.util.Map;

import edu.uiuc.ncsa.security.core.Logable;

public class CertExtensionGenerator {

	protected Map<String, String> extensionSources;

	protected Logable logger;
	
	public CertExtensionGenerator(Map<String, String> extensionSources, Logable logger) {
		this.extensionSources = extensionSources;
		this.logger = logger;
	}
	
	/**
	 * Returns addition information that has to be added as extension into the end entity
	 * certificate. Extensions will be presented in the form of key=value pairs
	 * concatenated with a whitespace. This collection of extensions has to be 
	 * passed to the MyProxy Server appended to the USERNAME request parameter.
	 * <p>
	 * Currently, this method only supports the EMAIL extensions. If you would like to get 
	 * other additional information (extensions) in your EEC, extend this method. 
	 * 
	 * @param trans The current service transaction
	 * @return The extensions that will be requested
	 */
	public String getCertificateExtensions(Map<String, Object> attributeMap) {
		
		String extensions = "";

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
					extensions +=  " " + extName + "=" + ((String) ext);
					i++;
					
				} else if ( ext instanceof List ) {
					// the extension value can be multi-valued. 
					// in this case add them all as separate key=value pairs
					List<String> attrList = ((List<String>)ext);
					for ( String v : attrList ) {
						extensions += " " + extName + "=" + v;
						i++;
					}					

				} else {
					logger.error("Unexpected instance for attribute " + extName +". Was expecting either String or List<String>");
					return null;			
				}
				
				logger.debug("	- Added " + i + " extensions with name '" + extName + "'");
				
			}
		}
		
		return extensions;
	}
	

	
}
