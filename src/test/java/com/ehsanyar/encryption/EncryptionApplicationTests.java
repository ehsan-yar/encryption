package com.ehsanyar.encryption;

import com.ehsanyar.encryption.service.dukpt.Dukpt;
import com.ehsanyar.encryption.service.rsa.RSAEncryption;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.UnsupportedEncodingException;

@RunWith(SpringRunner.class)
@SpringBootTest
public class EncryptionApplicationTests {

	@Autowired
	private RSAEncryption rsaEncryption;

	@Autowired
	private Dukpt dukpt;


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


    @Test
    public void testDukptWithAesEncrypt() throws Exception {
		dukptTest("AES");

    }

	@Test
	public void testDukptWithDesEncrypt() throws Exception {
		dukptTest("DES");

	}

	@Test
	public void testDukptWith3DesEncrypt() throws Exception {
		dukptTest("3DES");

	}

    private void dukptTest(String algorithm) throws Exception {

		// Setup
		String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
		String ksnHexString = "FFFF9876543210E00008";
		String payloadString = "My name is Ehsan Yar Mohammadi";

		System.out.println("Payload: "+payloadString);

		byte[] bdk = dukpt.toByteArray(bdkHexString);
		byte[] ksn = dukpt.toByteArray(ksnHexString);

		byte[] encryptedPayload;
		byte[] decryptedPayload = null;

		// Action
		byte[] key = dukpt.computeKey(bdk, ksn);

		if (algorithm.toLowerCase().equals("aes")) {
			encryptedPayload = dukpt.encryptAes(key, payloadString.getBytes("UTF-8"));
			decryptedPayload = dukpt.decryptAes(key, encryptedPayload);
		}

		if (algorithm.toLowerCase().equals("des")) {
			encryptedPayload = dukpt.encryptDes(key, payloadString.getBytes("UTF-8"));
			decryptedPayload = dukpt.decryptDes(key, encryptedPayload, true);
		}

		if (algorithm.toLowerCase().equals("3des")) {
			encryptedPayload = dukpt.encryptTripleDes(key, payloadString.getBytes("UTF-8"));
			decryptedPayload = dukpt.decryptTripleDes(key, encryptedPayload);
		}

		assert decryptedPayload != null;
		String dataOutput = new String(decryptedPayload, "UTF-8").trim();

		System.out.println("Decrypted: " + dataOutput);

		// Assert
		Assert.assertEquals(payloadString, dataOutput);


	}
}
