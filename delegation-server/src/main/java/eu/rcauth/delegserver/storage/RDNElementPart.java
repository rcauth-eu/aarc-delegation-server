package eu.rcauth.delegserver.storage;

public class RDNElementPart {

	/* A single RDN element. This can be either a full RDN or a partial RDN */
	protected String element;
	/* The original value(s) of the RDN element */
	protected String elementOrig;
	/* The source attribute name(s) of RDN element */
	protected String elementSource;
	
	public RDNElementPart() {
	}
	
	public RDNElementPart(String element, String elementOrig, String elementSource) {
		this.element = element;
		this.elementOrig = elementOrig;
		this.elementSource = elementSource;
	}
	
	public void setElement(String element) {
		this.element = element;
	}
	
	public void setElementOrig(String elementOrig) {
		this.elementOrig = elementOrig;
	}
	
	public void setElementSource(String elementSource) {
		this.elementSource = elementSource;
	}
	
	public String getElement() {
		return element;
	}
	
	public String getElementOrig() {
		return elementOrig;
	}
	
	public String getElementSource() {
		return elementSource;
	}
	
	@Override
	public String toString() {
		return element;
	}
	
}
