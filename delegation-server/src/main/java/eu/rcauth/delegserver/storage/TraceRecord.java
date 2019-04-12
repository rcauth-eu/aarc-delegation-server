package eu.rcauth.delegserver.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

import java.util.List;


public class TraceRecord extends IdentifiableImpl {

	private static final long serialVersionUID = -7707448168067694856L;

	protected int sequenceNr = 0;	
	protected String attrHash;
	protected String attrSalt;	
	protected List<String> attrNames;
	
	//keep in memory, but don't serialize to trace record 
	protected RDNElement commonName;
	protected RDNElement organization;
	
	
	public TraceRecord(TraceRecordIdentifier identifier) {
		super(identifier);
	}
	
	/* GETTERS AND SETTERS */
	
	public void setCommonName(RDNElement commonName) {
		this.commonName = commonName;
	}
	
	public void setOrganization(RDNElement organization) {
		this.organization = organization;
	}
	
	public RDNElement getCommonName() {
		return commonName;
	}
	
	public RDNElement getOrganization() {
		return organization;
	}
	
	@Override
	public void setIdentifier(Identifier identifier) {
		super.setIdentifier(identifier);
	}
		
	public String getCnHash() {
		return ((TraceRecordIdentifier)this.getIdentifier()).cnHash;
	}
	
	public String getAttrHash() {
		return attrHash;
	}
	
	public List<String> getAttrNames() {
		return attrNames;
	}
	
	public void setCnHash(String cnHash) {
		this.setIdentifier(new TraceRecordIdentifier(cnHash));
	}
	
	public void setAttrHash(String attrHash) {
		this.attrHash = attrHash;
	}
	
	public void setAttrNames(List<String> attrNames) {
		this.attrNames = attrNames;
	}
	
	public String getAttrSalt() {
		return attrSalt;
	}
	
	public void setAttrSalt(String attrSalt) {
		this.attrSalt = attrSalt;
	}
	
	public int getSequenceNr() {
		return sequenceNr;
	}
	
	public void setSequenceNr(int sequenceNr) {
		this.sequenceNr = sequenceNr;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (super.equals(obj) && obj instanceof TraceRecord) {
			TraceRecord rec = (TraceRecord) obj;
			return checkEquals(getCnHash(), rec.getCnHash()) &&
					this.getSequenceNr() == rec.getSequenceNr() &&
					checkEquals(getAttrHash(), rec.getAttrHash()) &&
					//checkEquals(getAttrNames(), rec.getAttrNames()) &&
					checkEquals(getAttrSalt(), rec.getAttrSalt());
		}
		return false;
	}
	
	@Override
	public String toString() {
		return "TraceRecord: \n" + 
			   "	cnHash=" + getIdentifierString() + "\n" +
			   "	sequenceNr=" + sequenceNr + "\n" +
	           "	attrHash=" + attrHash + "\n" + 
	           "	attrSalt=" + attrSalt + "\n" +   
			   "	attributeNames=" + attrNames + "\n";
	}
	
}
