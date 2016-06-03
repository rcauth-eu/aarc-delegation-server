package org.delegserver.oauth2.generator;

import java.util.List;
import java.util.Map;

import org.delegserver.oauth2.util.ShibAttrParser;

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
		
		for (String extName : extensionSources.keySet()) {
		
			Object ext = attributeMap.get( extensionSources.get(extName) ); 
			
			if ( ext == null ) {
				logger.warn("");
			} else {
				
				if ( ext instanceof String ) {
					extensions +=  " " + extName + "=" + ((String) ext);
					
				} else if ( ext instanceof List ) {
					List<String> attrList = ((List<String>)ext);
					for ( String v : attrList ) {
						extensions += " " + extName + "=" + v;
					}					

				} else {
					logger.error("Unexpected instance for attribute " + extName +". Was expecting either String or List<String>");
					return null;			
				}
			}
		}
		
		return extensions;
	}
	

	
}
