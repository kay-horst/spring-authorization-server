/*
 * Copyright 2020-2022 the original author or authors.
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
package sample.web.authentication;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for the OAuth 2.0 Device Authorization Endpoint.
 * 
 * @author Steve Riesenberg
 * @since 0.4.0
 * @see OAuth2DeviceAuthorizationEndpointFilter
 */
public final class OAuth2DeviceAuthorizationEndpointConfigurer
		extends AbstractHttpConfigurer<OAuth2DeviceAuthorizationEndpointConfigurer, HttpSecurity> {

	private AuthenticationConverter authorizationRequestConverter;
	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
	private AuthenticationSuccessHandler deviceAuthorizationResponseHandler;
	private AuthenticationFailureHandler errorResponseHandler;
	private String deviceAuthorizationEndpointUrl = OAuth2DeviceAuthorizationEndpointFilter.DEFAULT_DEVICE_AUTHORIZATION_ENDPOINT_URI;

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2AuthorizationCodeRequestAuthenticationToken} used for authenticating the request.
	 *
	 * @param authorizationRequestConverter the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer authorizationRequestConverter(AuthenticationConverter authorizationRequestConverter) {
		this.authorizationRequestConverter = authorizationRequestConverter;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}.
	 *
	 * @param authenticationProvider an {@link AuthenticationProvider} used for authenticating an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 * and returning the Device Authorization Response.
	 *
	 * @param deviceAuthorizationResponseHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer authorizationResponseHandler(AuthenticationSuccessHandler deviceAuthorizationResponseHandler) {
		this.deviceAuthorizationResponseHandler = deviceAuthorizationResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	/**
	 * Sets the {@code URI} for the OAuth 2.0 Device Authorization Endpoint.
	 *
	 * TODO: This could eventually be moved into ProviderSettings.
	 *
	 * @param deviceAuthorizationEndpointUrl the {@code URI} for the OAuth 2.0 Device Authorization Endpoint
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer deviceAuthorizationEndpointUrl(String deviceAuthorizationEndpointUrl) {
		this.deviceAuthorizationEndpointUrl = deviceAuthorizationEndpointUrl;
		return this;
	}

	@Override
	public void init(HttpSecurity builder) {
		List<AuthenticationProvider> authenticationProviders =
				!this.authenticationProviders.isEmpty() ?
						this.authenticationProviders :
						createDefaultAuthenticationProviders(builder);
		authenticationProviders.forEach(authenticationProvider ->
				builder.authenticationProvider(postProcess(authenticationProvider)));
	}

	@Override
	public void configure(HttpSecurity builder) {
		AuthenticationManager authenticationManager =
				builder.getSharedObject(AuthenticationManager.class);

		OAuth2ClientAuthenticationFilter clientAuthenticationFilter =
				new OAuth2ClientAuthenticationFilter(authenticationManager, getRequestMatcher());

		OAuth2DeviceAuthorizationEndpointFilter deviceAuthorizationEndpointFilter =
				new OAuth2DeviceAuthorizationEndpointFilter(authenticationManager, this.deviceAuthorizationEndpointUrl);

		if (this.authorizationRequestConverter != null) {
			deviceAuthorizationEndpointFilter.setAuthenticationConverter(this.authorizationRequestConverter);
		}
		if (this.deviceAuthorizationResponseHandler != null) {
			deviceAuthorizationEndpointFilter.setAuthenticationSuccessHandler(this.deviceAuthorizationResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			deviceAuthorizationEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}

		// Device Authorization Endpoint requires client authentication with a custom matcher
		builder.addFilterAfter(postProcess(clientAuthenticationFilter), AbstractPreAuthenticatedProcessingFilter.class);
		builder.addFilterAfter(postProcess(deviceAuthorizationEndpointFilter), FilterSecurityInterceptor.class);
	}

	public RequestMatcher getRequestMatcher() {
		return new AntPathRequestMatcher(this.deviceAuthorizationEndpointUrl);
	}

	private static List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity builder) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		// TODO: This assumes beans are available
		ApplicationContext applicationContext =
				builder.getSharedObject(ApplicationContext.class);
		RegisteredClientRepository registeredClientRepository =
				applicationContext.getBean(RegisteredClientRepository.class);
		OAuth2AuthorizationService authorizationService =
				applicationContext.getBean(OAuth2AuthorizationService.class);
		OAuth2AuthorizationConsentService authorizationConsentService =
				applicationContext.getBean(OAuth2AuthorizationConsentService.class);
		OAuth2DeviceService deviceService =
				applicationContext.getBean(OAuth2DeviceService.class);

		OAuth2DeviceAuthorizationRequestAuthenticationProvider deviceAuthorizationRequestAuthenticationProvider =
				new OAuth2DeviceAuthorizationRequestAuthenticationProvider(authorizationService, deviceService);
		authenticationProviders.add(deviceAuthorizationRequestAuthenticationProvider);

		OAuth2DeviceActivationAuthenticationProvider deviceActivationAuthenticationProvider =
				new OAuth2DeviceActivationAuthenticationProvider(
						registeredClientRepository, authorizationService, authorizationConsentService, deviceService);
		authenticationProviders.add(deviceActivationAuthenticationProvider);

		return authenticationProviders;
	}

}
