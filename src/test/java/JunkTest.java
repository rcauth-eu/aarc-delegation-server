import static org.junit.Assert.*;

import org.junit.Test;

public class JunkTest {

	@Test
	public void test() {
		String username = "https://centos7-shibboleth-idp-bd.novalocal/idp/shibboleth!https://centos7-clean-slave-bd1.novalocal!OJvHyRSO+Lj/sA4i7niEGW1KslE=";
		String escapedUsername = username.replaceAll("\\/", "\\\\\\\\/");
		escapedUsername = escapedUsername.replaceAll("=", "\\\\\\\\=");
		System.out.println("ESCAPED USERNAME: " + escapedUsername);
	}

}
