package io.mosip.kernel.auth.defaultadapter.config;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.cloud.client.loadbalancer.reactive.LoadBalancerExchangeFilterFunction;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.helper.TokenHelper;
import io.mosip.kernel.auth.defaultadapter.helper.TokenValidationHelper;
import io.mosip.kernel.auth.defaultadapter.model.TokenHolder;
import io.mosip.kernel.core.util.EmptyCheckUtils;
import io.mosip.kernel.openid.bridge.model.AuthUserDetails;

@Configuration
@EnableScheduling
public class BeanConfig {

	@Autowired
	private TokenHelper tokenHelper;

	@Autowired
	private Environment environment;

	@Autowired
	private RestTemplateInterceptor defaultInterceptor;

	@Value("${mosip.kernel.auth.adapter.ssl-bypass:true}")
	private boolean sslBypass;

	@Value("${mosip.kernel.http.default.restTemplate.max-connection-per-route:20}")
	private Integer defaultRestTemplateMaxConnectionPerRoute;

	@Value("${mosip.kernel.http.default.restTemplate.total-max-connections:100}")
	private Integer defaultRestTemplateTotalMaxConnections;

	@Value("${mosip.kernel.http.selftoken.restTemplate.max-connection-per-route:20}")
	private Integer selfTokenRestTemplateMaxConnectionPerRoute;

	@Value("${mosip.kernel.http.selftoken.restTemplate.total-max-connections:100}")
	private Integer selfTokenRestTemplateTotalMaxConnections;

	@Value("${mosip.kernel.http.plain.restTemplate.max-connection-per-route:20}")
	private Integer plainRestTemplateMaxConnectionPerRoute;

	@Value("${mosip.kernel.http.plain.restTemplate.total-max-connections:100}")
	private Integer plainRestTemplateTotalMaxConnections;

	@Autowired
	private TokenValidationHelper tokenValidationHelper;

	@Autowired(required = false)
	private LoadBalancerClient loadBalancerClient;

	@Bean
	public RestTemplate restTemplate() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		HttpClientBuilder httpClientBuilder = HttpClients.custom()
				.setMaxConnPerRoute(defaultRestTemplateMaxConnectionPerRoute)
				.setMaxConnTotal(defaultRestTemplateTotalMaxConnections).disableCookieManagement();
		RestTemplate restTemplate = null;
		if (sslBypass) {
			TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
			SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
					.loadTrustMaterial(null, acceptingTrustStrategy).build();
			SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new HostnameVerifier() {
				public boolean verify(String arg0, SSLSession arg1) {
					return true;
				}
			});
			httpClientBuilder.setSSLSocketFactory(csf);
		}
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(httpClientBuilder.build());
		restTemplate = new RestTemplate(requestFactory);
		restTemplate.setInterceptors(Collections.singletonList(new RequesterTokenRestInterceptor()));
		// interceptor added in RestTemplatePostProcessor
		return restTemplate;
	}

	// this is just used by client token interceptor to call to renew and validate
	// token
	@Bean
	public RestTemplate plainRestTemplate() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException{
		HttpClientBuilder httpClientBuilder = HttpClients.custom()
				.setMaxConnPerRoute(plainRestTemplateMaxConnectionPerRoute)
				.setMaxConnTotal(plainRestTemplateTotalMaxConnections).disableCookieManagement();
		RestTemplate restTemplate = null;
		if (sslBypass) {
			TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
			SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
					.loadTrustMaterial(null, acceptingTrustStrategy).build();
			SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new HostnameVerifier() {
				public boolean verify(String arg0, SSLSession arg1) {
					return true;
				}
			});
			httpClientBuilder.setSSLSocketFactory(csf);
		}
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(httpClientBuilder.build());
		RestTemplate template = new RestTemplate(requestFactory);
		template.setInterceptors(Collections.singletonList(defaultInterceptor));
		return template;
	}

	@Bean
	public TokenHolder<String> cachedTokenObject() {
		return new TokenHolder<>();
	}

	@Bean
	public RestTemplate selfTokenRestTemplate(@Autowired @Qualifier("plainRestTemplate") RestTemplate plainRestTemplate,
			@Autowired TokenHolder<String> cachedTokenObject)
			throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		HttpClientBuilder httpClientBuilder = HttpClients.custom()
				.setMaxConnPerRoute(selfTokenRestTemplateMaxConnectionPerRoute)
				.setMaxConnTotal(selfTokenRestTemplateTotalMaxConnections).disableCookieManagement();
		RestTemplate restTemplate = null;
		if (sslBypass) {
			TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
			SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
					.loadTrustMaterial(null, acceptingTrustStrategy).build();
			SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new HostnameVerifier() {
				public boolean verify(String arg0, SSLSession arg1) {
					return true;
				}
			});
			httpClientBuilder.setSSLSocketFactory(csf);
		}
		String applName = getApplicationName();
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(httpClientBuilder.build());
		restTemplate = new RestTemplate(requestFactory);
		restTemplate.setInterceptors(Collections.singletonList(new SelfTokenRestInterceptor(environment,
				plainRestTemplate, cachedTokenObject, tokenHelper, tokenValidationHelper, applName)));
		// interceptor added in RestTemplatePostProcessor
		return restTemplate;
	}

	@Bean
	public WebClient plainWebClient() {
		ExchangeFilterFunction filterFunction = (loadBalancerClient != null)
				? new LoadBalancerExchangeFilterFunction(loadBalancerClient)
				: (req, next) -> {
					return next.exchange(req);
				};
		return WebClient.builder().filter(filterFunction).build();
	}

	@Bean
	public SelfTokenRenewalTaskExecutor selfTokenRenewTaskExecutor(@Autowired TokenHolder<String> cachedTokenObject,
			@Autowired @Qualifier("plainWebClient") WebClient plainWebClient)
			throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		String applName = getApplicationName();
		return new SelfTokenRenewalTaskExecutor(cachedTokenObject, plainWebClient, tokenHelper, environment, applName);
	}

	@Bean
	public WebClient webClient() {

		return WebClient.builder().filter((req, next) -> {
			ClientRequest filtered = null;
			if (SecurityContextHolder.getContext() != null
					&& SecurityContextHolder.getContext().getAuthentication().getPrincipal() != null
					&& SecurityContextHolder.getContext().getAuthentication()
							.getPrincipal() instanceof AuthUserDetails) {
				io.mosip.kernel.openid.bridge.model.AuthUserDetails userDetail = (AuthUserDetails) SecurityContextHolder.getContext().getAuthentication()
						.getPrincipal();
				filtered = ClientRequest.from(req).header(AuthAdapterConstant.AUTH_HEADER_COOKIE,
						AuthAdapterConstant.AUTH_HEADER + userDetail.getToken()).build();
			}
			return next.exchange(filtered);
		}).build();
	}

	@Bean
	public WebClient selfTokenWebClient(@Autowired @Qualifier("plainWebClient") WebClient plainWebClient,
			@Autowired TokenHolder<String> cachedTokenObject) {
		String applName = getApplicationName();
		return WebClient.builder().filter(new SelfTokenExchangeFilterFunction(environment, plainWebClient,
				cachedTokenObject, tokenHelper, tokenValidationHelper, applName)).build();
	}

	private String getApplicationName() {
		String appNames = environment.getProperty("spring.application.name");
		if (!EmptyCheckUtils.isNullEmpty(appNames)) {
			List<String> appNamesList = Stream.of(appNames.split(",")).collect(Collectors.toList());
			return appNamesList.get(0);
		} else {
			throw new RuntimeException("Property spring.application.name not found");
		}
	}
}
