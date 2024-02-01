package io.mosip.kernel.auth.defaultadapter.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import io.mosip.kernel.auth.defaultadapter.model.ServiceEndPoint;
import io.mosip.kernel.auth.defaultadapter.model.GlobalEndPoint;
import lombok.Data;

/**
 * @author GOVINDARAJ VELU
 * It is used to store all end-points which will access without authentication
 *
 */
@Configuration
@ConfigurationProperties(prefix = "mosip")
@Data
public class NoAuthenticationEndPoint {

	private GlobalEndPoint global;
	private ServiceEndPoint service;
	private String serviceContext;
}