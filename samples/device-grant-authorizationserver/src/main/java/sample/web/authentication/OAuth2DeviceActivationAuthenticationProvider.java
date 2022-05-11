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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * @author Steve Riesenberg
 * @since 0.3.0
 */
public final class OAuth2DeviceActivationAuthenticationProvider implements AuthenticationProvider {
	private static final OAuth2TokenType AUTHORIZATION_CODE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

	private final OAuth2AuthorizationService authorizationService;
	private final OAuth2DeviceService deviceService;

	private final OAuth2AuthorizationCodeRequestAuthenticationProvider delegate;

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationConsentService the authorization consent service
	 * @param deviceService the device service
	 */
	public OAuth2DeviceActivationAuthenticationProvider(
			RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService,
			OAuth2AuthorizationConsentService authorizationConsentService,
			OAuth2DeviceService deviceService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(authorizationConsentService, "authorizationConsentService cannot be null");
		Assert.notNull(deviceService, "deviceService cannot be null");
		this.authorizationService = authorizationService;
		this.deviceService = deviceService;
		this.delegate = new OAuth2AuthorizationCodeRequestAuthenticationProvider(
				registeredClientRepository, authorizationService, authorizationConsentService);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.delegate.authenticate(authentication);

		OAuth2AuthorizationCode authorizationCode = authorizationCodeRequestAuthentication.getAuthorizationCode();
		if (authorizationCode != null) {
			OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCode.getTokenValue(),
					AUTHORIZATION_CODE);
			OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
					OAuth2AuthorizationRequest.class.getName());
			String userCode = (String) authorizationRequest.getAdditionalParameters().get(OAuth2ParameterNames.CODE);
			OAuth2Device device = this.deviceService.findByUserCode(userCode);
			if (device == null) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
			}

			// Update device with generated authorization code
			device = OAuth2Device.with(device)
					.authorizationCode(authorizationCode.getTokenValue())
					.build();
			this.deviceService.save(device);
		}

		return authorizationCodeRequestAuthentication;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return this.delegate.supports(authentication);
	}

}
