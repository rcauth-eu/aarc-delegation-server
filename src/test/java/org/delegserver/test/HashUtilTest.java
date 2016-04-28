package org.delegserver.test;

import org.delegserver.oauth2.util.HashingUtils;
import org.junit.Test;

public class HashUtilTest {

	
	@Test
	public void testSaltedHashToBase64() {
		
		HashingUtils hasher =  HashingUtils.getInstance();
		
		String input = "D. Dummyson,Dummy,Dummyson,Dummy Dummyson,dummy@novalocal,KedUbrH3A9+V8uSoP9ci77RCUtA=";
		byte[] salt = hasher.getRandomSalt();
		
		hasher.saltedHashToBase64(input, salt);
		
	}
	
}
