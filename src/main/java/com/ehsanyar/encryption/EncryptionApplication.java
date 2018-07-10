package com.ehsanyar.encryption;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableAutoConfiguration
public class EncryptionApplication {

	public static void main(String[] args) {
		SpringApplication.run(EncryptionApplication.class, args);
	}
}
