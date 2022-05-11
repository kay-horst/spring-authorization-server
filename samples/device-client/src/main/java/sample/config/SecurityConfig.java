/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import sample.repository.DeviceRepository;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author Steve Riesenberg
 * @since 0.3.0
 */
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().antMatchers("/webjars/**", "/assets/**");
	}

	// @formatter:off
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize -> authorize
				.mvcMatchers("/").permitAll()
				.anyRequest().authenticated()
			)
			.formLogin(Customizer.withDefaults())
			.oauth2Client(Customizer.withDefaults());
		return http.build();
	}
	// @formatter:on

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user1")
				.password("password")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}

	@Bean
	public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
		ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
				new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		return WebClient.builder()
				.apply(oauth2Client.oauth2Configuration())
				.build();
	}

	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			DeviceRepository deviceRepository) {

		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken()
						.provider(new DeviceCodeOAuth2AuthorizedClientProvider())
						.build();
		DefaultOAuth2AuthorizedClientManager authorizedClientManager =
				new DefaultOAuth2AuthorizedClientManager(
						clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
		authorizedClientManager.setContextAttributesMapper(deviceCodeContextAttributesMapper(deviceRepository));

		return authorizedClientManager;
	}

	private Function<OAuth2AuthorizeRequest, Map<String, Object>> deviceCodeContextAttributesMapper(
			DeviceRepository deviceRepository) {
		return authorizeRequest -> {
			HttpServletRequest request = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
			Assert.notNull(request, "request cannot be null");

			// Look up device code via user code
			String userCode = request.getParameter("code");
			String deviceCode = deviceRepository.findDeviceCodeByUserCode(userCode)
					.orElseThrow(() -> {
						OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
						return new OAuth2AuthorizationException(oauth2Error);
					});

			return Collections.singletonMap("device_code", deviceCode);
		};
	}

	public static final class OAuth2DeviceGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

		private static final AuthorizationGrantType GRANT_TYPE = new AuthorizationGrantType(
				"urn:ietf:params:oauth:grant-type:device_code");

		private final String deviceCode;

		public OAuth2DeviceGrantRequest(ClientRegistration clientRegistration, String deviceCode) {
			super(GRANT_TYPE, clientRegistration);
			this.deviceCode = deviceCode;
		}

		public String getDeviceCode() {
			return deviceCode;
		}

	}

	public static final class DeviceCodeOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {

		private OAuth2AccessTokenResponseClient<OAuth2DeviceGrantRequest> accessTokenResponseClient =
				new OAuth2DeviceAccessTokenResponseClient();

		private Duration clockSkew = Duration.ofSeconds(60);

		private Clock clock = Clock.systemUTC();

		public DeviceCodeOAuth2AuthorizedClientProvider() {
		}

		public void setAccessTokenResponseClient(OAuth2AccessTokenResponseClient<OAuth2DeviceGrantRequest> accessTokenResponseClient) {
			this.accessTokenResponseClient = accessTokenResponseClient;
		}

		public void setClockSkew(Duration clockSkew) {
			this.clockSkew = clockSkew;
		}

		public void setClock(Clock clock) {
			this.clock = clock;
		}

		@Override
		public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
			Assert.notNull(context, "context cannot be null");
			ClientRegistration clientRegistration = context.getClientRegistration();
			if (!OAuth2DeviceGrantRequest.GRANT_TYPE.equals(clientRegistration.getAuthorizationGrantType())) {
				return null;
			}
			OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
			if (authorizedClient != null && !hasTokenExpired(authorizedClient.getAccessToken())) {
				// If client is already authorized but access token is NOT expired than no
				// need for re-authorization
				return null;
			}
			if (authorizedClient != null && authorizedClient.getRefreshToken() != null) {
				// If client is already authorized but access token is expired and a
				// refresh token is available, delegate to refresh_token.
				return null;
			}
			// *****************************************************************
			// Get device_code set via DefaultOAuth2AuthorizedClientManager#setContextAttributesMapper()
			// *****************************************************************
			String deviceCode = context.getAttribute("device_code");
			// Attempt to authorize the client, which will repeatedly fail until the user grants authorization
			OAuth2DeviceGrantRequest deviceGrantRequest = new OAuth2DeviceGrantRequest(clientRegistration, deviceCode);
			OAuth2AccessTokenResponse tokenResponse = getTokenResponse(clientRegistration, deviceGrantRequest);
			return new OAuth2AuthorizedClient(clientRegistration, context.getPrincipal().getName(),
					tokenResponse.getAccessToken());
		}

		private OAuth2AccessTokenResponse getTokenResponse(ClientRegistration clientRegistration,
				OAuth2DeviceGrantRequest deviceGrantRequest) {
			try {
				return this.accessTokenResponseClient.getTokenResponse(deviceGrantRequest);
			}
			catch (OAuth2AuthorizationException ex) {
				throw new ClientAuthorizationException(ex.getError(), clientRegistration.getRegistrationId(), ex);
			}
		}

		private boolean hasTokenExpired(OAuth2Token token) {
			return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
		}

	}

	public static final class OAuth2DeviceAccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2DeviceGrantRequest> {

		private RestOperations restOperations;

		public OAuth2DeviceAccessTokenResponseClient() {
			RestTemplate restTemplate = new RestTemplate(Arrays.asList(new FormHttpMessageConverter(),
					new OAuth2AccessTokenResponseHttpMessageConverter()));
			restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
			this.restOperations = restTemplate;
		}

		public void setRestOperations(RestOperations restOperations) {
			this.restOperations = restOperations;
		}

		@Override
		public OAuth2AccessTokenResponse getTokenResponse(OAuth2DeviceGrantRequest deviceGrantRequest) {
			ClientRegistration clientRegistration = deviceGrantRequest.getClientRegistration();

			HttpHeaders headers = new HttpHeaders();
			headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());

			MultiValueMap<String, Object> requestParameters = new LinkedMultiValueMap<>();
			requestParameters.add(OAuth2ParameterNames.GRANT_TYPE, deviceGrantRequest.getGrantType().getValue());
			requestParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
			requestParameters.add("device_code", deviceGrantRequest.getDeviceCode());

			// @formatter:off
			RequestEntity<MultiValueMap<String, Object>> requestEntity =
					RequestEntity.post(deviceGrantRequest.getClientRegistration().getProviderDetails().getTokenUri())
							.headers(headers)
							.body(requestParameters);
			// @formatter:on

			try {
				return this.restOperations.exchange(requestEntity, OAuth2AccessTokenResponse.class).getBody();
			} catch (RestClientException ex) {
				OAuth2Error oauth2Error = new OAuth2Error("invalid_token_response",
						"An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
								+ ex.getMessage(), null);
				throw new OAuth2AuthorizationException(oauth2Error, ex);
			}
		}
	}

}
