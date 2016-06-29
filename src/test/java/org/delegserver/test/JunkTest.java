package org.delegserver.test;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;

import org.delegserver.oauth2.util.HashingUtils;
import org.junit.Test;

public class JunkTest {

	@Test
	public void test() {
		String username = "https://centos7-shibboleth-idp-bd.novalocal/idp/shibboleth!https://centos7-clean-slave-bd1.novalocal!OJvHyRSO+Lj/sA4i7niEGW1KslE=";
		String escapedUsername = username.replaceAll("\\/", "\\\\\\\\/");
		escapedUsername = escapedUsername.replaceAll("=", "\\\\\\\\=");
		System.out.println("ESCAPED USERNAME: " + escapedUsername);
	}
	
	@Test
	public void test2() {
		String source = "givenName+sn";
		String[] sources = source.split("\\+");
		System.out.println("SOURCES CNT: " + sources.length);
		System.out.println("SOURCES CNT: " + sources[0]);
		System.out.println("SOURCES CNT: " + sources[1]);
	}	
	
	
	@Test
	public void test3() throws UnsupportedEncodingException {
		String source = "asdáé";
		byte[] b = source.getBytes();
		byte[] b_utf8 = source.getBytes("UTF-8");
		System.out.println("BYTE LENGTH: " + b.length);
		System.out.println("BYTE LENGTH (UTF-8): " + b_utf8.length);
		System.out.println("STRING LENGTH: " + source.length());
		System.out.println("STRING LENGTH: " + source.charAt(3));
		
	}	
	
	@Test
	public void test4() throws UnsupportedEncodingException {
		String string = "ááé\uD834\uDD1Eéúww";
		int DB_FIELD_LENGTH = 10;
		
		System.out.println("BEFORE:\n");
		
		System.out.println("STRING LENGTH: " + string.length());
		System.out.println("BYTE LENGTH (UTF-8): " + string.getBytes("UTF-8").length);
		System.out.println("STRING: " + string);
		System.out.println("---------------------------------------------------");
		System.out.println("AFTER:\n");		
		
		Charset utf8Charset = Charset.forName("UTF-8");
		CharsetDecoder cd = utf8Charset.newDecoder();
		byte[] sba = string.getBytes("UTF-8");
		// Ensure truncating by having byte buffer = DB_FIELD_LENGTH
		ByteBuffer bb = ByteBuffer.wrap(sba, 0, DB_FIELD_LENGTH); // len in [B]
		CharBuffer cb = CharBuffer.allocate(DB_FIELD_LENGTH); // len in [char] <= # [B]
		// Ignore an incomplete character
		cd.onMalformedInput(CodingErrorAction.IGNORE);
		cd.decode(bb, cb, true);
		cd.flush(cb);
		string = new String(cb.array(), 0, cb.position());
		
		System.out.println("STRING LENGTH: " + string.length());
		System.out.println("BYTE LENGTH (UTF-8): " + string.getBytes("UTF-8").length);
		System.out.println("STRING: " + string);
	}

	@Test
	public void test5() {
		
		String nr = "05";
		int i = Integer.parseInt(nr);
		
		System.out.println( nr + " = " + i );
		
	}
	
	@Test
	public void test6() {
		
		String string = "asdasd+asd=asd+//asd==";
		
		//string = string.replace('+', 'X').replace('/', 'X').replace('=', 'X');
	
		System.out.println( HashingUtils.getInstance().hashToHEX(string) );
		
		
	}
	
}
