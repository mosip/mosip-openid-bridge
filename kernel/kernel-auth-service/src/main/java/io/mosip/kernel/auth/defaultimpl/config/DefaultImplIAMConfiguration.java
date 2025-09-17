package io.mosip.kernel.auth.defaultimpl.config;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

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

	// Tunables (override via application.properties if needed)
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
	@Primary
	public RestTemplate getRestTemplate() {
		// Connection pool + TTL
		PoolingHttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
				.setMaxConnTotal(maxTotal)
				.setMaxConnPerRoute(maxPerRoute)
				.setConnectionTimeToLive(TimeValue.ofSeconds(poolTtlSeconds))
				.build();

		// Timeouts (HC5 uses Timeout objects)
		RequestConfig rc = RequestConfig.custom()
				.setConnectTimeout(Timeout.ofMilliseconds(connectTimeoutMs))
				.setResponseTimeout(Timeout.ofMilliseconds(socketTimeoutMs))
				.setConnectionRequestTimeout(Timeout.ofMilliseconds(connectionRequestTimeoutMs))
				.build();

		CloseableHttpClient httpClient = HttpClients.custom()
				.setConnectionManager(cm)
				.setDefaultRequestConfig(rc)
				.evictIdleConnections(TimeValue.ofSeconds(idleEvictSeconds))
				.evictExpiredConnections()
				.disableAutomaticRetries() // avoid accidental duplicates
				.build();

		HttpComponentsClientHttpRequestFactory rf = new HttpComponentsClientHttpRequestFactory(httpClient);

		RestTemplate restTemplate = new RestTemplate(rf);
		// Add gzip header + your auth interceptor
		restTemplate.setInterceptors(Arrays.asList(
				(req, body, exec) -> {
					req.getHeaders().set("Accept-Encoding", "gzip");
					return exec.execute(req, body);
				},
				restInterceptor
		));
		return restTemplate;
	}

}
