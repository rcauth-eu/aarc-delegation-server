package org.delegserver.storage;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

public class UserAttributeTrace implements Serializable {

	private static final long serialVersionUID = 4758985408987211526L;

	// It can take the value of 'eppn'
	String eppn = null;
	String[] eppnCandidates = null;
	
	// It can take the values of 'eptid' or 'persistent_id'
	String persistentId = null;
	String[] persistentIdCandidates = null;
	
	// It can take the values of 'cn' or 'displayName', or as an alternative: 'givenName + sn' 
	String name = null;
	String[] nameCandidates = null;
	String[] nameAlternative1 = null;
	
	List<String> attributeNames = null;
	List<String> attributeValues = null;
	
	public UserAttributeTrace() {
		init();
	}
	
	public UserAttributeTrace(Map parameterMap) throws Throwable {
		fromParameterMap(parameterMap);
	}
	
	
	private void init() {
		eppnCandidates = new String[1];
		eppnCandidates[0] = "eppn";
		
		persistentIdCandidates = new String[2];
		persistentIdCandidates[0] = "eptid";
		persistentIdCandidates[1] = "persistent-id";
		
		nameCandidates = new String[2];
		nameCandidates[0] = "cn";
		nameCandidates[1] = "displayName";
		
		nameAlternative1 = new String[2];
		nameAlternative1[0] = "givenName";
		nameAlternative1[1] = "sn";
		
		attributeNames = new ArrayList<String>();
		attributeValues = new ArrayList<String>();		
	}
	
	public void fromParameterMap(Map parameterMap) throws Throwable {
		
		init();
		
		for (int i=0; i<eppnCandidates.length ; i++) {
			if ( parameterMap.containsKey(eppnCandidates[i]) &&
				 ! ((String) parameterMap.get(eppnCandidates[i])).isEmpty()) {
				
				eppn = (String) parameterMap.get(eppnCandidates[i]);
				attributeNames.add(eppnCandidates[i]);
				break;
			}
		}

		for (int i=0; i<persistentIdCandidates.length ; i++) {
			if ( parameterMap.containsKey(persistentIdCandidates[i]) &&
			     ! ((String) parameterMap.get(persistentIdCandidates[i])).isEmpty()) {
				
				persistentId = (String) parameterMap.get(persistentIdCandidates[i]);
				attributeNames.add(persistentIdCandidates[i]);
				break;
			}
		}
		
		if ( eppn == null && persistentId == null ) {
			throw new GeneralException("No approproate identifier parameter! Either 'eppn' or 'eptid' or 'persistent_id' is expected!");
		}
		
		for (int i=0; i<nameCandidates.length ; i++) {
			if ( parameterMap.containsKey(nameCandidates[i]) ) {
				name = (String) parameterMap.get(nameCandidates[i]);
				attributeNames.add(nameCandidates[i]);
				break;
			}
		}
		
		if ( name == null ) {
			String nameTmp = null;
			for (int i=0; i<nameAlternative1.length; i++) {
				if ( parameterMap.containsKey(nameAlternative1[i]) ) {
					if ( nameTmp == null ) {
						nameTmp = (String) parameterMap.get(nameAlternative1[i]);
					} else {
						nameTmp += " " + parameterMap.get(nameAlternative1[i]);
					}
				} else {
					throw new GeneralException("No approproate name parameter! Either 'cn' or 'displayName' or ('givenName','sn') is expected!");
				}
			}
			attributeNames.addAll( Arrays.asList(nameAlternative1)  );
			name = nameTmp;
		}
		
		attributeValues.add(eppn);
		attributeValues.add(persistentId);
		attributeValues.add(name);
	}
	
	
	public List<String> getAttributeValues() {
		return attributeValues;
	}
	
	public List<String> getAttributeNames() {
		return attributeNames;
	}
	
}
