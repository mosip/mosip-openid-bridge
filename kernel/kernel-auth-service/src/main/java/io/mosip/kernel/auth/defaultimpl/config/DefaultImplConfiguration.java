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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import io.mosip.kernel.auth.defaultimpl.dto.AccessTokenResponse;
import io.mosip.kernel.auth.defaultimpl.intercepter.RestInterceptor;
import io.mosip.kernel.auth.defaultimpl.util.MemoryCache;
import io.mosip.kernel.auth.defaultimpl.util.TokenValidator;

@Configuration
public class DefaultImplConfiguration {

	// Tunables (override in application.properties as needed)
	@Value("${iam.http.maxTotal:200}")
	private int maxTotal;
	@Value("${iam.http.maxPerRoute:50}")
	private int maxPerRoute;
	@Value("${iam.http.connectTimeoutMs:2000}")
	private int connectTimeoutMs;
	@Value("${iam.http.responseTimeoutMs:5000}")
	private int responseTimeoutMs;
	@Value("${iam.http.connectionRequestTimeoutMs:2000}")
	private int connectionRequestTimeoutMs;
	@Value("${iam.http.pool.ttl.seconds:30}")
	private int poolTtlSeconds;
	@Value("${iam.http.idleEvict.seconds:30}")
	private int idleEvictSeconds;

	@Primary
	@Bean(name = "authRestTemplate")
	public RestTemplate restTemplate() {
		// Pooling + TTL
		PoolingHttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
				.setMaxConnTotal(maxTotal)
				.setMaxConnPerRoute(maxPerRoute)
				.setConnectionTimeToLive(TimeValue.ofSeconds(poolTtlSeconds))
				.build();

		// Timeouts
		RequestConfig rc = RequestConfig.custom()
				.setConnectTimeout(Timeout.ofMilliseconds(connectTimeoutMs))
				.setResponseTimeout(Timeout.ofMilliseconds(responseTimeoutMs))
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

		RestTemplate rt = new RestTemplate(rf);
		// Add gzip header first; your RestInterceptor will inject auth headers
		rt.setInterceptors(Arrays.asList(
				(req, body, exec) -> {
					req.getHeaders().set("Accept-Encoding", "gzip");
					return exec.execute(req, body);
				}
		));
		return rt;
	}

	@Bean
	public MemoryCache<String, AccessTokenResponse> memoryCache() {
		return new MemoryCache<>(1);
	}
	

	@Bean
	public RestInterceptor restInterceptor(
			@Autowired MemoryCache<String, AccessTokenResponse> memoryCache,
			@Autowired TokenValidator tokenValidator,
			@Qualifier("authRestTemplate") @Autowired RestTemplate restTemplate) {
		return new RestInterceptor(memoryCache, tokenValidator, restTemplate);
	}
}
