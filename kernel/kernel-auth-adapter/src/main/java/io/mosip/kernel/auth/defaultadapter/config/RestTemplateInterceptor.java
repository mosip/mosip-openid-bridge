package io.mosip.kernel.auth.defaultadapter.config;

import java.io.IOException;
import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;


/***********************************************************************************************************************
 * It is used to intercept any http calls made using rest template from this
 * application.
 *
 * CONFIG: This is added to the list of interceptors in the RestTemplate bean
 * created in the SecurityConfig.
 *
 * TASKS: 1. Intercept all the requests from the application and do the below
 * tasks. 2. Intercept a request to add auth token to the "Authorization"
 * header. 3. Intercept a response to modify the stored token with the
 * "Authorization" header of the response.
 *
 * @author Sabbu Uday Kumar
 * @author Ramadurai Saravana Pandian
 * @author Raj Jha
 * @since 1.0.0
 **********************************************************************************************************************/

@Component
public class RestTemplateInterceptor implements ClientHttpRequestInterceptor {

	private static final Logger LOGGER = LoggerFactory.getLogger(RestTemplateInterceptor.class);

	@Autowired(required = false)
	private LoadBalancerClient loadBalancerClient;


	@Override
	public ClientHttpResponse intercept(HttpRequest httpRequest, byte[] bytes,
			ClientHttpRequestExecution clientHttpRequestExecution) throws IOException {
		
		httpRequest = resolveServiceId(httpRequest);
		return clientHttpRequestExecution.execute(httpRequest, bytes);
	}

	private HttpRequest resolveServiceId(HttpRequest request) {
		try {
			if(loadBalancerClient != null) {
				LOGGER.debug("Injected load balancer : {} ", loadBalancerClient.toString());
				ServiceInstance instance = loadBalancerClient.choose(request.getURI().getHost());
				if (instance != null) {
					final URI newUri = loadBalancerClient.reconstructURI(instance, request.getURI());
					LOGGER.debug("Resolved service [{}] -> {}", request.getURI().getHost(), newUri);

					// Wrap the original request so only the URI changes
					return new org.springframework.http.client.support.HttpRequestWrapper(request) {
						@Override
						public URI getURI() {
							return newUri;
						}
					};
				}
			}
		} catch (Exception ex) {
			LOGGER.warn("Failed to choose service instance : {}",ex.getMessage());
		}
		return request;
	}

}