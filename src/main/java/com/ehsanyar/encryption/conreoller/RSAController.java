package com.ehsanyar.encryption.conreoller;


import com.ehsanyar.encryption.service.rsa.RSAEncryption;
import com.ehsanyar.encryption.service.rsa.RSAUpdateKeysScheduler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("rsa/")
public class RSAController {


    private final RSAEncryption rsaEncryption;
    private final RSAUpdateKeysScheduler RSAUpdateKeysScheduler;


    @Autowired
    public RSAController(RSAEncryption rsaEncryption, RSAUpdateKeysScheduler RSAUpdateKeysScheduler) {
        this.rsaEncryption = rsaEncryption;
        this.RSAUpdateKeysScheduler = RSAUpdateKeysScheduler;
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


    @GetMapping("setUpdateKeysDuration")
    public String updateKeys(@RequestHeader("duration") long time){
        RSAUpdateKeysScheduler.setTime(time);
        return String.format("Time changed to : %d second", time);
    }

}
