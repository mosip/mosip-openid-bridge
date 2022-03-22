package io.mosip.kernel.auth.defaultadapter.config;

import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.auth.defaultadapter.exception.AuthAdapterException;
import io.mosip.kernel.auth.defaultadapter.helper.TokenHelper;
import io.mosip.kernel.auth.defaultadapter.helper.TokenValidationHelper;
import io.mosip.kernel.auth.defaultadapter.model.TokenHolder;
import reactor.core.publisher.Mono;
/**
 * This class filters and renew auth client token.
 * 
 * @author Mahammed Taheer
 *
 */
public class SelfTokenExchangeFilterFunction implements ExchangeFilterFunction {

    private static final Logger LOGGER = LoggerFactory.getLogger(SelfTokenExchangeFilterFunction.class);
    
    private String clientID;

	private String clientSecret;

	private String appID;

	private TokenHolder<String> cachedToken;
	
	private TokenHelper tokenHelper;

	private TokenValidationHelper tokenValidationHelper;

    private WebClient webClient;

    public SelfTokenExchangeFilterFunction(Environment environment, WebClient webClient,
                    TokenHolder<String> cachedToken, TokenHelper tokenHelper, TokenValidationHelper tokenValidationHelper,
                    String applName) {
        clientID = environment.getProperty("mosip.iam.adapter.clientid." + applName, environment.getProperty("mosip.iam.adapter.clientid", ""));
        clientSecret = environment.getProperty("mosip.iam.adapter.clientsecret." + applName, environment.getProperty("mosip.iam.adapter.clientsecret", ""));
        appID = environment.getProperty("mosip.iam.adapter.appid." + applName, environment.getProperty("mosip.iam.adapter.appid", ""));
        this.cachedToken = cachedToken;
        this.webClient = webClient;
        this.tokenHelper = tokenHelper;
        this.tokenValidationHelper = tokenValidationHelper;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        
        // null check if job is not able to fetch client id secret
		if (cachedToken.getToken() == null) {
            // try requesting new token. Added because IDA need the token before it gets created by the scheduler thread.
            String authToken = tokenHelper.getClientToken(clientID, clientSecret, appID, webClient);
			if (Objects.isNull(authToken)) {
			    LOGGER.error("there is some issue with getting token with clienid and secret");
			    throw new AuthAdapterException(AuthAdapterErrorCode.SELF_AUTH_TOKEN_NULL.getErrorCode(),
					AuthAdapterErrorCode.SELF_AUTH_TOKEN_NULL.getErrorMessage());
            }
            cachedToken.setToken(authToken);
		}
        
        ClientRequest newReq = ClientRequest.from(request).header(AuthAdapterConstant.AUTH_HEADER_COOKIE,
						AuthAdapterConstant.AUTH_HEADER + cachedToken.getToken()).build();
        Mono<ClientResponse>  clientResponse = next.exchange(newReq);
        ClientResponse response = clientResponse.block();
	if (response != null && response.statusCode() != HttpStatus.UNAUTHORIZED) {
            return Mono.just(response);
        }

        synchronized (this) {
			// online validation
			if(!isTokenValid(cachedToken.getToken())) {
				String authToken = tokenHelper.getClientToken(clientID, clientSecret, appID, webClient);
				cachedToken.setToken(authToken);		
			}
		}

        List<String> cookies = request.headers().get(AuthAdapterConstant.AUTH_HEADER_COOKIE);
		if (cookies != null && !cookies.isEmpty()) {
			cookies = cookies.stream().filter(str -> !str.contains(AuthAdapterConstant.AUTH_HEADER)).collect(Collectors.toList());
		}
        request.headers().replace(AuthAdapterConstant.AUTH_HEADER_COOKIE, cookies);
        request.headers().add(AuthAdapterConstant.AUTH_HEADER_COOKIE,
                        AuthAdapterConstant.AUTH_HEADER + cachedToken.getToken());
        return next.exchange(request);
    }

    // Updated to use common code to validate the token online.
	private boolean isTokenValid(String authToken) {
		return Objects.nonNull(tokenValidationHelper.doOnlineTokenValidation(authToken, webClient));
	}
}
