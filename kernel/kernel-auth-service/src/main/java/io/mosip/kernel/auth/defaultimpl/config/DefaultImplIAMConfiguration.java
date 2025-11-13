package io.mosip.kernel.auth.defaultimpl.config;

import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import io.mosip.kernel.auth.defaultimpl.intercepter.RestInterceptor;

@Configuration
public class DefaultImplIAMConfiguration {

	@Autowired
	private RestInterceptor restInterceptor;

	@Value("${iam.http.maxTotal:200}")
	private int maxTotal;

	@Value("${iam.http.maxPerRoute:50}")
	private int maxPerRoute;

	@Value("${iam.http.connectTimeoutMs:2000}")
	private int connectTimeoutMs;

	@Value("${iam.http.socketTimeoutMs:5000}")
	private int socketTimeoutMs;

	@Value("${iam.http.connectionRequestTimeoutMs:2000}")
	private int connectionRequestTimeoutMs;

	@Value("${iam.http.pool.ttl.seconds:30}")
	private int poolTtlSeconds;

	@Value("${iam.http.idleEvict.seconds:30}")
	private int idleEvictSeconds;

	@Bean(name = "keycloakRestTemplate")
	public RestTemplate keycloakRestTemplate() {
		// Connection pool configuration
		PoolingHttpClientConnectionManager connectionManager =
				PoolingHttpClientConnectionManagerBuilder.create()
						.setMaxConnTotal(maxTotal)
						.setMaxConnPerRoute(maxPerRoute)
						.setConnectionTimeToLive(TimeValue.ofSeconds(poolTtlSeconds))
						.build();

		// Timeout configuration
		RequestConfig requestConfig = RequestConfig.custom()
				.setConnectTimeout(Timeout.ofMilliseconds(connectTimeoutMs))
				.setResponseTimeout(Timeout.ofMilliseconds(socketTimeoutMs))
				.setConnectionRequestTimeout(Timeout.ofMilliseconds(connectionRequestTimeoutMs))
				.build();

		// Build HttpClient
		CloseableHttpClient httpClient = HttpClients.custom()
				.setConnectionManager(connectionManager)
				.setDefaultRequestConfig(requestConfig)
				.evictIdleConnections(TimeValue.ofSeconds(idleEvictSeconds))
				.evictExpiredConnections()
				.disableAutomaticRetries() // avoid duplicate requests on retry
				.build();

		// Create factory and RestTemplate
		HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);

		RestTemplate restTemplate = new RestTemplate(factory);
		restTemplate.setInterceptors(java.util.Collections.singletonList(restInterceptor));
		return restTemplate;
	}
}
