package org.delegserver.oauth2.util;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base64;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

public class HashingUtils {

	protected MessageDigest defaultMessageDigest = null;
	protected SecureRandom defualtRandomGenerator = null;
	protected  Charset defaultCharset = null;
	
	/* SINGLETON */
	
	private static HashingUtils instance = null;

	
	private HashingUtils() {
	
		try {
			
			defaultCharset = Charset.forName("UTF-8");
			defualtRandomGenerator = SecureRandom.getInstance("SHA1PRNG");
			defaultMessageDigest = MessageDigest.getInstance("SHA-256");
			
		} catch (NoSuchAlgorithmException e) {
			throw new GeneralException("Can't create HashingUtils!",e);
		}
		
	}
		
	public static HashingUtils getInstance() {
		if ( instance == null ) {
			instance = new HashingUtils();
		}
		return instance;
	}
	
	/* HASHING HELPER METHODS */
	
	public String hashToBase64(String input) {
		
		// hash the input
		byte[] hash = defaultMessageDigest.digest( input.getBytes(defaultCharset) );
		
		// get the base64 encoding of the hash from the previous step
		byte[] encodedHash =  Base64.encodeBase64(hash);
		
		return new String(encodedHash);		
	}
	
	public String saltedHashToBase64(String input) {
		return saltedHashToBase64(input, getRandomSalt() );
	}
	
	public String saltedHashToBase64(String input, byte[] salt) {
	
		// combine input with salt
		String saltedInput = salt + input; 
		
		// hash the salted input
		byte[] saltedHash = defaultMessageDigest.digest( saltedInput.getBytes(defaultCharset) );
		
		// get the base64 encoding of the salted hash from the previous step
		byte[] encodedHash =  Base64.encodeBase64(saltedHash);
		
		return new String(encodedHash);		
	}	
	
	public byte[] getRandomSalt() {
		
		// generate salt
		byte[] salt = new byte[32];
		defualtRandomGenerator.nextBytes(salt);
		
		return salt;
	}
	
}
