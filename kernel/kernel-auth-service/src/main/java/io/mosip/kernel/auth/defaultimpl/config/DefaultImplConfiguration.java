package io.mosip.kernel.auth.defaultimpl.config;

import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import io.mosip.kernel.auth.defaultimpl.dto.AccessTokenResponse;
import io.mosip.kernel.auth.defaultimpl.intercepter.RestInterceptor;
import io.mosip.kernel.auth.defaultimpl.util.MemoryCache;
import io.mosip.kernel.auth.defaultimpl.util.TokenValidator;

@Configuration
public class DefaultImplConfiguration {
	
	@Value("${authmanager.default.httpclient.connections.max.per.host:20}")
	private int maxConnectionPerRoute;

	@Value("${authmanager.default.httpclient.connections.max:100}")
	private int totalMaxConnection;
	

	@Primary
	@Bean(name = "authRestTemplate")
	public RestTemplate restTemplate() {
		HttpClientBuilder httpClientBuilder = HttpClients.custom()
				.setMaxConnPerRoute(maxConnectionPerRoute)
				.setMaxConnTotal(totalMaxConnection).disableCookieManagement();
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(httpClientBuilder.build());
		return new RestTemplate(requestFactory);
	}

	@Bean
	public MemoryCache<String, AccessTokenResponse> memoryCache() {
		return new MemoryCache<>(1);
	}
	

	@Bean
	public RestInterceptor restInterceptor(@Autowired  MemoryCache<String, AccessTokenResponse> memoryCache,@Autowired TokenValidator tokenValidator,@Qualifier("authRestTemplate") @Autowired RestTemplate restTemplate) {
		return new RestInterceptor(memoryCache,tokenValidator,restTemplate);
	}
}
