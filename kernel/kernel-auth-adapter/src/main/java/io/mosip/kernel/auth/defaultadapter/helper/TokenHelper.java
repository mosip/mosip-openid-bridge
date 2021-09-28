package io.mosip.kernel.auth.defaultadapter.helper;

import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.auth.defaultadapter.exception.AuthAdapterException;
import io.mosip.kernel.auth.defaultadapter.exception.AuthRestException;
import io.mosip.kernel.core.authmanager.model.ClientSecret;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.util.DateUtils;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class TokenHelper {

	private static final Logger LOGGER = LoggerFactory.getLogger(TokenHelper.class);

	@Autowired
	private ObjectMapper mapper;

	public String getClientToken(String clientID, String clienSecret, String appID, RestTemplate restTemplate,
			String tokenURL) {
		if (tokenURL == null || "".equals(tokenURL)) {
			LOGGER.warn("Auth Service URL is not available in config file, not requesting for new auth token.");
			return null;
		}
		
		RequestWrapper<ClientSecret> requestWrapper = new RequestWrapper<>();
		ClientSecret clientCred = new ClientSecret();
		clientCred.setAppId(appID);
		clientCred.setClientId(clientID);
		clientCred.setSecretKey(clienSecret);
		requestWrapper.setRequest(clientCred);
		HttpEntity<String> response = null;
		try {
			response = restTemplate.postForEntity(tokenURL, requestWrapper, String.class);
		} catch (HttpServerErrorException | HttpClientErrorException e) {
			LOGGER.error("error connecting to auth service {}", e.getResponseBodyAsString());
		}
		if (response == null) {
			LOGGER.error("error connecting to auth service {}", AuthAdapterErrorCode.CANNOT_CONNECT_TO_AUTH_SERVICE.getErrorMessage());
			return null;
		}
		String responseBody = response.getBody();
		List<ServiceError> validationErrorList = ExceptionUtils.getServiceErrorList(responseBody);
		if (!validationErrorList.isEmpty()) {
			throw new AuthRestException(validationErrorList);
		}
		HttpHeaders headers = response.getHeaders();
		List<String> cookies = headers.get(AuthAdapterConstant.AUTH_HEADER_SET_COOKIE);
		if (cookies == null || cookies.isEmpty())
			throw new AuthAdapterException(AuthAdapterErrorCode.IO_EXCEPTION.getErrorCode(),
					AuthAdapterErrorCode.IO_EXCEPTION.getErrorMessage());

		String authToken = cookies.get(0).split(";")[0].split(AuthAdapterConstant.AUTH_HEADER)[1];

		return authToken;
	}

	public String getClientToken(String clientID, String clientSecret, String appID, WebClient webClient,
			String tokenURL) {
		if (tokenURL == null || "".equals(tokenURL)) {
			LOGGER.warn("Auth Service URL is not available in config file, not requesting for new auth token.");
			return null;
		}
		
		ObjectNode requestBody = mapper.createObjectNode();
		requestBody.put("clientId", clientID);
		requestBody.put("secretKey", clientSecret);
		requestBody.put("appId", appID);
		RequestWrapper<ObjectNode> request = new RequestWrapper<>();
		request.setRequesttime(DateUtils.getUTCCurrentDateTime());
		request.setRequest(requestBody);

		ClientResponse response = webClient.method(HttpMethod.POST)
										   .uri(UriComponentsBuilder.fromUriString(tokenURL).toUriString())
										   .syncBody(request).exchange().block();
		if (response.statusCode() == HttpStatus.OK) {
			ObjectNode responseBody = response.bodyToMono(ObjectNode.class).block();
			List<ServiceError> validationErrorsList = ExceptionUtils.getServiceErrorList(responseBody.asText());
            if (!validationErrorsList.isEmpty()) {
                throw new AuthRestException(validationErrorsList);
            }

			if (responseBody != null && responseBody.get("response").get("status").asText().equalsIgnoreCase("success")) {
				ResponseCookie responseCookie = response.cookies().get(AuthAdapterConstant.AUTH_REQUEST_COOOKIE_HEADER).get(0);
				return responseCookie.getValue();
			}
		} 

		LOGGER.error("error connecting to auth service (WebClient) {}", AuthAdapterErrorCode.CANNOT_CONNECT_TO_AUTH_SERVICE.getErrorMessage());
		return null;
	}
}
