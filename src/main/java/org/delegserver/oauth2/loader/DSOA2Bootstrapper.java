package org.delegserver.oauth2.loader;

import javax.servlet.ServletContext;

import org.apache.commons.configuration.tree.ConfigurationNode;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2Bootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

public class DSOA2Bootstrapper extends OA2Bootstrapper {

	
	@Override
	public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
		return new DSOA2ConfigurationLoader(node);
	}
	
	
}
