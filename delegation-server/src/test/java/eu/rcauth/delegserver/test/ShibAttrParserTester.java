package eu.rcauth.delegserver.test;

import org.junit.Test;
import static org.junit.Assert.*;

import eu.rcauth.delegserver.oauth2.shib.ShibAttrParser;

public class ShibAttrParserTester {

	
	@Test
	public void testSingleAttr() {
		
		String attr1 = "single_attribute";
		String[] val1 = ShibAttrParser.parseMultiValuedAttr(attr1);
		String[] expVal1 = {"single_attribute"};
		assertArrayEquals( val1 , expVal1 );
		
		String attr2 = "single\\;attribute";
		String[] val2 = ShibAttrParser.parseMultiValuedAttr(attr2);
		String[] expVal2 = {"single;attribute"};
		assertArrayEquals( val2 , expVal2 );		
		
	}

	@Test
	public void testSingleDelimitedAttr() {
		
		String attr1 = "single_attribute;;;";
		String[] val1 = ShibAttrParser.parseMultiValuedAttr(attr1);
		String[] expVal1 = {"single_attribute"};
		assertArrayEquals( val1 , expVal1 );
		
		String attr2 = ";;;single\\;attribute";
		String[] val2 = ShibAttrParser.parseMultiValuedAttr(attr2);
		String[] expVal2 = {"single;attribute"};
		assertArrayEquals( val2 , expVal2 );		
		
	}	

	@Test
	public void testMultiAttr() {
		
		String attr1 = "multi1;multi2";
		String[] val1 = ShibAttrParser.parseMultiValuedAttr(attr1);
		String[] expVal1 = {"multi1", "multi2"};
		assertArrayEquals( val1 , expVal1 );
		
		String attr2 = "multi1;multi2;multi3";
		String[] val2 = ShibAttrParser.parseMultiValuedAttr(attr2);
		String[] expVal2 = {"multi1" , "multi2" , "multi3"};
		assertArrayEquals( val2 , expVal2 );	
		
		String attr3 = "multi1\\;;multi2;mul\\;ti3";
		String[] val3 = ShibAttrParser.parseMultiValuedAttr(attr3);
		String[] expVal3 = {"multi1;" , "multi2" , "mul;ti3"};
		assertArrayEquals( val3 , expVal3 );	
		
	}	

	
	@Test
	public void testMultiDelimitedAttr() {
		
		String attr1 = "multi1;multi2;;;";
		String[] val1 = ShibAttrParser.parseMultiValuedAttr(attr1);
		String[] expVal1 = {"multi1", "multi2"};
		assertArrayEquals( val1 , expVal1 );
		
		String attr2 = ";;;;multi1;multi2;multi3";
		String[] val2 = ShibAttrParser.parseMultiValuedAttr(attr2);
		String[] expVal2 = {"multi1" , "multi2" , "multi3"};
		assertArrayEquals( val2 , expVal2 );	
		
		String attr3 = ";;multi1\\;;multi2;mul\\;ti3;;";
		String[] val3 = ShibAttrParser.parseMultiValuedAttr(attr3);
		String[] expVal3 = {"multi1;" , "multi2" , "mul;ti3"};
		assertArrayEquals( val3 , expVal3 );	
		
	}	
	
	@Test
	public void testMultiDuplicateAttr() {
		
		String attr1 = "multi1;multi1";
		String[] val1 = ShibAttrParser.parseMultiValuedAttr(attr1);
		String[] expVal1 = {"multi1"};
		assertArrayEquals( val1 , expVal1 );
		
		String attr2 = "multi1;multi2;multi1";
		String[] val2 = ShibAttrParser.parseMultiValuedAttr(attr2);
		String[] expVal2 = {"multi1" , "multi2"};
		assertArrayEquals( val2 , expVal2 );		
		
	}		
	
}
