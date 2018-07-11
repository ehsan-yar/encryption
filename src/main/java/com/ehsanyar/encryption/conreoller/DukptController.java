package com.ehsanyar.encryption.conreoller;

import com.ehsanyar.encryption.service.dukpt.Dukpt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("dukpt/")
public class DukptController {

    private static final String BDK_TEST = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key

    private final Dukpt dukpt;


    @Autowired
    public DukptController(Dukpt dukpt) {
        this.dukpt = dukpt;
    }


    /*
    * Actually BDK provided by HSM ot TRSM
    * return hard code sample of bdk
    * */
    @GetMapping("bdk")
    public String getBdk(){
        return BDK_TEST;
    }

    @GetMapping("encrypt")
    public byte[] encrypt(@RequestHeader("ksn") String ksn , @RequestHeader("message") String message ,@RequestHeader("algorithm") String algorithm) throws Exception {

        byte[] messageBytes = dukpt.toByteArray(message);
        byte[] key = dukpt.computeKey(dukpt.toByteArray(BDK_TEST), dukpt.toByteArray(ksn));

        if (algorithm.toLowerCase().equals("aes")) {
            return dukpt.encryptAes(key, messageBytes);
        }

        if (algorithm.toLowerCase().equals("des")) {
            return dukpt.encryptDes(key, messageBytes);
        }

        if (algorithm.toLowerCase().equals("3des")) {
            return dukpt.encryptTripleDes(key, messageBytes);
        }

        return null;
    }


    @GetMapping("decrypt")
    public byte[] decrypt(@RequestHeader("ksn") String ksn , @RequestHeader("message") String message ,@RequestHeader("algorithm") String algorithm) throws Exception {

        byte[] messageBytes = dukpt.toByteArray(message);
        byte[] key = dukpt.computeKey(dukpt.toByteArray(BDK_TEST), dukpt.toByteArray(ksn));

        if (algorithm.toLowerCase().equals("aes")) {
            return dukpt.decryptAes(key, messageBytes);
        }

        if (algorithm.toLowerCase().equals("des")) {
            return dukpt.decryptDes(key, messageBytes);
        }

        if (algorithm.toLowerCase().equals("3des")) {
            return dukpt.decryptTripleDes(key, messageBytes);
        }

        return null;
    }


}
