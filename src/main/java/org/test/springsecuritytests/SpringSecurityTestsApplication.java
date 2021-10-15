package org.test.springsecuritytests;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication (
		exclude = { SecurityAutoConfiguration.class })
public class  SpringSecurityTestsApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityTestsApplication.class, args);
	}

}
