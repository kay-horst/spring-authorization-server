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

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Device Authorization Request
 * used in the Device Authorization Grant.
 *
 * @author Steve Riesenberg
 * @since 0.4.0
 * @see OAuth2DeviceAuthorizationRequestAuthenticationToken
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.1">Section 3.1 Device Authorization Request</a>
 */
public final class OAuth2DeviceAuthorizationRequestAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private static final String DEFAULT_VERIFICATION_URI = "/activate";

	private static final StringKeyGenerator DEFAULT_STATE_GENERATOR =
			new Base64StringKeyGenerator(Base64.getUrlEncoder());

	private final OAuth2AuthorizationService authorizationService;
	private String verificationUri = DEFAULT_VERIFICATION_URI;
	private OAuth2TokenGenerator<OAuth2DeviceCode> deviceCodeGenerator = new OAuth2DeviceCodeGenerator();
	private OAuth2TokenGenerator<OAuth2UserCode> userCodeGenerator = new OAuth2UserCodeGenerator();

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationRequestAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 */
	public OAuth2DeviceAuthorizationRequestAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	/**
	 * Sets the end-user verification {@code URI} on the authorization server.
	 *
	 * @param verificationUri the end-user verification {@code URI} on the authorization server
	 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.2">Section 3.2 Device Authorization Response</a>
	 */
	public void setVerificationUri(String verificationUri) {
		this.verificationUri = verificationUri;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2DeviceAuthorizationRequestAuthenticationToken deviceAuthorizationRequestAuthentication =
				(OAuth2DeviceAuthorizationRequestAuthenticationToken) authentication;

		// Client authentication is REQUIRED
		Authentication principal = (Authentication) deviceAuthorizationRequestAuthentication.getPrincipal();
		if (!OAuth2ClientAuthenticationToken.class.isAssignableFrom(principal.getClass())
				|| !principal.isAuthenticated()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		OAuth2ClientAuthenticationToken clientPrincipal = (OAuth2ClientAuthenticationToken) principal;
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
		Assert.notNull(registeredClient, "registeredClient cannot be null");

		// Validate client_id in request matches client authentication
		if (!registeredClient.getClientId().equals(deviceAuthorizationRequestAuthentication.getClientId())) {
			throwError(OAuth2ErrorCodes.INVALID_GRANT, OAuth2ParameterNames.CLIENT_ID);
		}

		// Validate client grant_type has device_code grant type
		if (!registeredClient.getAuthorizationGrantTypes().contains(OAuth2DeviceCode.GRANT_TYPE)) {
			throwError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.GRANT_TYPE);
		}

		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(deviceAuthorizationRequestAuthentication.getAuthorizationUri())
				.clientId(registeredClient.getClientId())
				.scopes(deviceAuthorizationRequestAuthentication.getScopes())
				.build();

		// Generate a state parameter
		String state = DEFAULT_STATE_GENERATOR.generateKey();

		// Generate a high-entropy string to use as the device code
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(clientPrincipal)
				.providerContext(ProviderContextHolder.getProviderContext())
				.tokenType(new OAuth2TokenType("device_code"))
				.authorizedScopes(deviceAuthorizationRequestAuthentication.getScopes())
				.authorizationGrantType(OAuth2DeviceCode.GRANT_TYPE)
				.authorizationGrant(deviceAuthorizationRequestAuthentication)
				.build();
		OAuth2DeviceCode deviceCode = this.deviceCodeGenerator.generate(tokenContext);
		Assert.notNull(deviceCode, "deviceCode cannot be null");

		// Generate a low-entropy string to use as the user code
		tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(clientPrincipal)
				.providerContext(ProviderContextHolder.getProviderContext())
				.tokenType(new OAuth2TokenType("user_code"))
				.authorizedScopes(deviceAuthorizationRequestAuthentication.getScopes())
				.authorizationGrantType(OAuth2DeviceCode.GRANT_TYPE)
				.authorizationGrant(deviceAuthorizationRequestAuthentication)
				.build();
		OAuth2UserCode userCode = this.userCodeGenerator.generate(tokenContext);
		Assert.notNull(userCode, "userCode cannot be null");

		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(clientPrincipal.getName())
				.authorizationGrantType(OAuth2DeviceCode.GRANT_TYPE)
				.token(deviceCode)
				.token(userCode)
				.attribute(Principal.class.getName(), clientPrincipal)
				.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
				.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, deviceAuthorizationRequestAuthentication.getScopes())
				.attribute(OAuth2ParameterNames.STATE, state)
				.build();
		this.authorizationService.save(authorization);

		// Generate the fully-qualified verification URI
		String issuerUri = ProviderContextHolder.getProviderContext().getIssuer();
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(issuerUri)
				.path(this.verificationUri);
		String verificationUri = uriComponentsBuilder
				.build()
				.toUriString();
		String verificationUriComplete = uriComponentsBuilder.queryParam("code", userCode)
				.build()
				.toUriString();

		return OAuth2DeviceAuthorizationRequestAuthenticationToken.with(registeredClient.getClientId(), clientPrincipal)
				.scopes(deviceAuthorizationRequestAuthentication.getScopes())
				.deviceCode(deviceCode.getTokenValue())
				.userCode(userCode.getTokenValue())
				.verificationUri(verificationUri)
				.verificationUriComplete(verificationUriComplete)
				.expiresIn(300)
				.interval(5)
				.build();
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2DeviceAuthorizationRequestAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

	private static final class UserCodeStringKeyGenerator implements StringKeyGenerator {

		private final BytesKeyGenerator keyGenerator;

		public UserCodeStringKeyGenerator() {
			this.keyGenerator = KeyGenerators.secureRandom(8);
		}

		@Override
		public String generateKey() {
			byte[] bytes = this.keyGenerator.generateKey();
			StringBuilder sb = new StringBuilder();
			for (byte b : bytes) {
				int offset = Math.abs(b % 26);
				sb.append((char) ('A' + offset));
			}
			return sb.toString();
		}

	}

	private static class OAuth2DeviceCodeGenerator implements OAuth2TokenGenerator<OAuth2DeviceCode> {

		private final StringKeyGenerator deviceCodeGenerator =
				new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

		@Nullable
		@Override
		public OAuth2DeviceCode generate(OAuth2TokenContext context) {
			if (context.getTokenType() == null ||
					!"device_code".equals(context.getTokenType().getValue())) {
				return null;
			}
			Instant issuedAt = Instant.now();
			Set<String> scopes = context.getAuthorizedScopes();
			return new OAuth2DeviceCode(this.deviceCodeGenerator.generateKey(), issuedAt, scopes);
		}

	}

	private static class OAuth2UserCodeGenerator implements OAuth2TokenGenerator<OAuth2UserCode> {

		private final StringKeyGenerator userCodeGenerator = new UserCodeStringKeyGenerator();

		@Nullable
		@Override
		public OAuth2UserCode generate(OAuth2TokenContext context) {
			if (context.getTokenType() == null || !"user_code".equals(context.getTokenType().getValue())) {
				return null;
			}
			Instant issuedAt = Instant.now();
			Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);
			return new OAuth2UserCode(this.userCodeGenerator.generateKey(), issuedAt, expiresAt);
		}

	}

}
