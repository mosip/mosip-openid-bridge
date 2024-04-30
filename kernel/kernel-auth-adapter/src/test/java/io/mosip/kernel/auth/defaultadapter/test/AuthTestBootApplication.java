package io.mosip.kernel.auth.defaultadapter.test;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

/**
 * The Class AuthTestBootApplication.
 */
@SpringBootApplication(scanBasePackages = { "io.mosip.kernel.auth.defaultadapter.*" },
exclude = { DataSourceAutoConfiguration.class })
public class AuthTestBootApplication {

	/**
	 * The main method.
	 *
	 * @param args the arguments
	 */
	public static void main(String[] args) {
		SpringApplication.run(AuthTestBootApplication.class, args);
	}

}
