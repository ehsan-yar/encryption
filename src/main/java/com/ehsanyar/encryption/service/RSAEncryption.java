package com.ehsanyar.encryption.service;



import org.apache.commons.codec.binary.Base64;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;

@Service
public class RSAEncryption {

    private static final Logger LOGGER = Logger.getLogger(RSAEncryption.class.getSimpleName());

    private static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";

    private static final int KEY_SIZE_2048 = 2048;
    private static final int KEY_SIZE_1024 = 1024;
    private static final String ALGORITHM = "RSA";

    private PrivateKey privateKey;
    private PublicKey publicKey;


    public RSAEncryption() {
        initiateAndUpdate();
    }

//    @Scheduled(cron = "0 0 0 ? * FRI") // Every Friday at 00:00 AM
//    @Scheduled(cron = "*/60 * * * * *") // every 60 second
    public void initiateAndUpdate(){
        KeyPair keyPair = generateKeyPair(KEY_SIZE_2048);
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        LOGGER.info("Initiate KeyPair");
    }


    public KeyPair generateKeyPair(int keySize){
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(keySize);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Failed to generate key pair!", e);
        }
    }


    public PublicKey getPublicKey(String base64PublicKey) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(base64PublicKey));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to get public key!", e);
        }
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public String getPublicKeyAsBase64() {
        return Base64.encodeBase64String(publicKey.getEncoded());
    }

    public PublicKey getPublicKey(BigInteger modulus, BigInteger exponent) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to get public key!", e);
        }
    }

    public String getBase64PublicKey(PublicKey publicKey) {
        return Base64.encodeBase64String(publicKey.getEncoded());
    }


    public PrivateKey getPrivateKey(String base64PrivateKey) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(base64PrivateKey));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            return privateKey;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to get private key!", e);
        }
    }


    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PrivateKey getPrivateKey(BigInteger modulus, BigInteger exponent) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, exponent);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to get private key!", e);
        }
    }

    public String getBase64PrivateKey(PrivateKey privateKey) {
        return Base64.encodeBase64String(privateKey.getEncoded());
    }

    public byte[] encryptAsByteArray(String data, PublicKey publicKey) {
        throwNullPointException(data);
        throwNullPointException(publicKey);
        try {
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            throw new IllegalArgumentException("Encrypt failed!", e);
        }
    }

    public byte[] encryptAsByteArray(String data, String base64PublicKey) {
        return encryptAsByteArray(data, getPublicKey(base64PublicKey));
    }

    public String encryptAsString(String data, PublicKey publicKey) {
        return Base64.encodeBase64String(encryptAsByteArray(data, publicKey));
    }

    public String encryptAsString(String data) {
        return Base64.encodeBase64String(encryptAsByteArray(data, this.publicKey));
    }

    public String encryptAsString(String data, String base64PublicKey) {
        return Base64.encodeBase64String(encryptAsByteArray(data, getPublicKey(base64PublicKey)));
    }

    public String decrypt(byte[] data, PrivateKey privateKey)  {
        throwNullPointException(data);
        throwNullPointException(privateKey);
        try {
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(data));
        } catch (Exception e) {
            throw new IllegalArgumentException("Decrypt failed!", e);
        }
    }

    public String decrypt(byte[] data, String base64PrivateKey) {
        return decrypt(data, getPrivateKey(base64PrivateKey));
    }

    public String decrypt(String data, PrivateKey privateKey)  {
        return decrypt(Base64.decodeBase64(data), privateKey);
    }

    public String decrypt(String data, String base64PrivateKey) {
        return decrypt(Base64.decodeBase64(data), getPrivateKey(base64PrivateKey));
    }

    public String decrypt(String data)  {
        return decrypt(Base64.decodeBase64(data), this.privateKey);
    }

    private void throwNullPointException(Object obj) {
        if (null == obj) {
            throw new NullPointerException();
        }
    }


}


