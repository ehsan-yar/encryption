package com.ehsanyar.encryption;

import com.ehsanyar.encryption.service.RSAEncryption;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class EncryptionApplicationTests {

	@Autowired
	private RSAEncryption rsaEncryption;



	@Test
	public void contextLoads() {

	}

	@Test
	public void RSATest(){

		String message = "Ehsan Yar 1991";
		System.out.println("Plain Message: " + message);

		String publicKeyAsBase64 = rsaEncryption.getPublicKeyAsBase64();
		System.out.println("PublicKey: " + publicKeyAsBase64);

		String encryptedMessage = rsaEncryption.encryptAsString(message, publicKeyAsBase64);
		System.out.println("EncryptedMessage: " + encryptedMessage);


		String decryptMessage = rsaEncryption.decrypt(encryptedMessage);
		System.out.println("DecryptMessage: " + decryptMessage);

		Assert.assertEquals(message,decryptMessage);

	}
}
