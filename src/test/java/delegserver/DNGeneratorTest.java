package delegserver;

import java.net.IDN;

import org.delegserver.oauth2.generator.DNGenerator;
import org.junit.Test;

public class DNGeneratorTest extends DNGenerator {

	public DNGeneratorTest() {
		super(null, null, null,null);
	}
	
	@Test
	public void testGetUSR() {
		
		//String inputAttr = "sakdfjasoaasdvnasjkvndkjvnajkenvvervrevvvvvvvvv";
		String inputAttr = "32r2róÓÜÓ??'/as.121#($#)($)>>\"\"?vvvvvvvv1212sakd!é!jkenvver";
		
		String inputUSR = this.getUSR(inputAttr);
		
		System.out.println("INPUT = " + inputAttr);
		System.out.println("INPUT USR = " + inputUSR);		
	}

	@Test
	public void testDNFormatter() {
		
		String org = "simple.org";
		String cn = "Simple Ton 45Ns0-21aaDX";
		
		String dn = String.format(DN_FORMAT, org, cn);
		System.out.println("DN = " + dn);
		
	}
	
	@Test
	public void testHostnameASCIIConversion() {

		String[] input = { "t\u00eatu.élpaaso.org", "\u8a00\u8a9e.net", "host.\u6e2c\u8a66",
				           "оживлённым.берегам.ru", "ваше здоровье"};

		for (String s : input) {
			System.out.println("IN  : " + s);
			System.out.println("OUT : " + this.getIDNString(s));
			System.out.println(" ================================ ");
		}
	    
	}
	
	@Test
	public void testDisplayNameSimplification() {
		String[] input = {"Jőzsi Bácsi\uc3a1" , "Ákom Bákom" , "T\u00eatu Elpasso" , "\u8a00\u8a9e \u6e2c\u8a66" ,
				          "оживлённым берегам", "君子務本", "φάω σπασμένα", "þess að meiða", "på mig",
				          "J'peux manger", "kācaṃ śaknomyattum", "ὕαλον ϕαγεῖν", "Michał Jankowski"};
		
		for (String s : input) {
			System.out.println("IN  : " + s);
			System.out.println("OUT : " + this.getPrintableString(s));
			System.out.println(" ================================ ");
		}
		
	}
	
	
}
