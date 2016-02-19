package org.delegserver.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

public class DNRecord extends IdentifiableImpl {

	private static final long serialVersionUID = -7707448168067694856L;

	public DNRecord(Identifier identifier) {
		super(identifier);
	}

	protected String dnHash;
	protected String attrHash;	
	protected String attributeList;
	
	public String getDnHash() {
		return dnHash;
	}
	
	public String getAttrHash() {
		return attrHash;
	}
	
	public String getAttributeList() {
		return attributeList;
	}
	
	public void setDnHash(String dnHash) {
		this.dnHash = dnHash;
	}
	
	public void setAttrHash(String attrHash) {
		this.attrHash = attrHash;
	}
	
	public void setAttributeList(String attributeList) {
		this.attributeList = attributeList;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (!super.equals(obj)) {
			return false;
		} else {
			if ( obj instanceof DNRecord) {
				DNRecord rec = (DNRecord) obj;
				if ( ! checkEquals(getDnHash(), rec.getDnHash()) ) return false;
				if ( ! checkEquals(getAttrHash(), rec.getAttrHash()) ) return false;
				if ( ! checkEquals(getAttributeList(), rec.getAttributeList()) ) return false;
				return true;				
			} else {
				return false;
			}
		}
	}
	
	@Override
	public String toString() {
		return "DNRecord: \n" + 
			   "dnHash=" + dnHash + "\n" +
	           "attrHash=" + attrHash + "\n" + 
			   "attributeList=" + attributeList + "\n";
	}
	
}
