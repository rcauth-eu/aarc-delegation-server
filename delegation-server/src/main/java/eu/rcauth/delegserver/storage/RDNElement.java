package eu.rcauth.delegserver.storage;

import java.util.ArrayList;
import java.util.List;

public class RDNElement {

	/* A single RDN element. This is the full RDN */
	protected String element;
	protected final List<RDNElementPart> elementParts;
	
	public RDNElement() {
		elementParts = new ArrayList<>();
	}
	
	public RDNElement(String element) {
		this();
		this.element = element;
	}
	
	public void setElement(String element) {
		this.element = element;
	}
	
	public String getElement() {
		return element;
	}
	
	public void addRDNElementPart(RDNElementPart elementPart) {
		elementParts.add(elementPart);
	}
	
	public List<RDNElementPart> getElementParts() {
		return elementParts;
	}
	
	@Override
	public String toString() {
		return element;
	}
	
}
