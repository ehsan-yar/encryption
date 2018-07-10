package com.ehsanyar.encryption.conreoller;


import com.ehsanyar.encryption.service.RSAEncryption;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("rsa/")
public class RSAController {


    private final RSAEncryption rsaEncryption;


    @Autowired
    public RSAController(RSAEncryption rsaEncryption) {
        this.rsaEncryption = rsaEncryption;
    }


    @GetMapping(value = "publicKey")
    public String getPublicKey(){
        return rsaEncryption.getPublicKeyAsBase64();

    }

    @GetMapping("encrypt")
    public String encryptMessage(@RequestHeader("key") String publikKey ,@RequestHeader("message") String message){

        return rsaEncryption.encryptAsString(message , publikKey);

    }

    @GetMapping("decrypt")
    public String decryptMessage(@RequestHeader("message") String encryptedMessage){
        return rsaEncryption.decrypt(encryptedMessage);
    }

}
