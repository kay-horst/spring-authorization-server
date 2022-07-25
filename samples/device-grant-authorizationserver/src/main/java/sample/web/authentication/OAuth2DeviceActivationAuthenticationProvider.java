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

import java.util.Set;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * @author Steve Riesenberg
 * @since 0.4.0
 */
public final class OAuth2DeviceActivationAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	private static final OAuth2TokenType USER_CODE_TOKEN_TYPE = new OAuth2TokenType("user_code");
	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final OAuth2AuthorizationConsentService authorizationConsentService;

	private final AuthenticationProvider delegate;

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationConsentService the authorization consent service
	 */
	public OAuth2DeviceActivationAuthenticationProvider(
			RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService,
			OAuth2AuthorizationConsentService authorizationConsentService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(authorizationConsentService, "authorizationConsentService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.authorizationConsentService = authorizationConsentService;
		this.delegate = new OAuth2AuthorizationCodeRequestAuthenticationProvider(
				registeredClientRepository, authorizationService, authorizationConsentService);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		if (authorizationCodeRequestAuthentication.isConsent()) {
			return this.delegate.authenticate(authentication);
		}

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				authorizationCodeRequestAuthentication.getClientId());
		if (registeredClient == null) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
		}

		Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
		if (!isPrincipalAuthenticated(principal)) {
			// Return the authorization request as-is where isAuthenticated() is false
			return authorizationCodeRequestAuthentication;
		}

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				authorizationCodeRequestAuthentication.getState(), STATE_TOKEN_TYPE);
		if (authorization == null) {
			throwError(OAuth2ErrorCodes.INVALID_GRANT, OAuth2ParameterNames.STATE);
		}

		OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
				registeredClient.getId(), principal.getName());

		Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ?
				currentAuthorizationConsent.getScopes() : null;

		if (requireAuthorizationConsent(registeredClient, authorizationCodeRequestAuthentication, currentAuthorizedScopes)) {
			// Update authorization to associate with the current principal
			OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
					.principalName(principal.getName())
					.build();
			this.authorizationService.save(updatedAuthorization);

			return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
					.authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
					.scopes(currentAuthorizedScopes)
					.state(authorizationCodeRequestAuthentication.getState())
					.consentRequired(true)
					.build();
		}

		// Return the authorization request as-is where isAuthenticated() is true
		return authorizationCodeRequestAuthentication;
	}

	private boolean requireAuthorizationConsent(RegisteredClient registeredClient, OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication, Set<String> currentAuthorizedScopes) {
		if (!registeredClient.getClientSettings().isRequireAuthorizationConsent()) {
			return false;
		}

		if (currentAuthorizedScopes != null
				&& currentAuthorizedScopes.containsAll(authorizationCodeRequestAuthentication.getScopes())) {
			return false;
		}

		return true;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return this.delegate.supports(authentication);
	}

	private static boolean isPrincipalAuthenticated(Authentication principal) {
		return principal != null &&
				!AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) &&
				principal.isAuthenticated();
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
