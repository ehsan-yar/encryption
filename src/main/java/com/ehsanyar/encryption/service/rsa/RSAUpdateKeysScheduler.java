package com.ehsanyar.encryption.service.rsa;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;


@Component
public class RSAUpdateKeysScheduler {

    private final RSAEncryption rsaEncryption;

    @Autowired
    public RSAUpdateKeysScheduler(RSAEncryption rsaEncryption, Environment environment) {
        this.rsaEncryption = rsaEncryption;

        Environment environment1 = environment;
        // set default time
        setTime(Long.valueOf(environment.getProperty("update-rsa-keys-default-duration")));
    }


    public void setTime(long duration) {
        Runnable task  = () -> rsaEncryption.initiateAndUpdate();
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(Runtime.getRuntime().availableProcessors());
        executor.schedule(task, duration, TimeUnit.SECONDS);

        executor.scheduleAtFixedRate(task, duration, duration, TimeUnit.SECONDS);

        executor.scheduleWithFixedDelay(task, duration, duration, TimeUnit.SECONDS);

    }

}