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

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * @author Steve Riesenberg
 * @since 0.4.0
 */
public final class OAuth2DeviceActivationAuthenticationConverter implements AuthenticationConverter {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
			"anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	private static final OAuth2TokenType USER_CODE_TOKEN_TYPE = new OAuth2TokenType("user_code");

	private final AuthenticationConverter delegate = new OAuth2AuthorizationCodeRequestAuthenticationConverter();
	private final OAuth2AuthorizationService authorizationService;

	public OAuth2DeviceActivationAuthenticationConverter(OAuth2AuthorizationService authorizationService) {
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		if ("POST".equals(request.getMethod())) {
			return this.delegate.convert(request);
		}

		// code (REQUIRED)
		String userCode = request.getParameter("code");
		if (!StringUtils.hasText(userCode)) {
			throwError(OAuth2ErrorCodes.INVALID_GRANT, "code");
		}

		// client_id (REQUIRED)
		String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId)) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
		}

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}

		OAuth2Authorization authorization = this.authorizationService.findByToken(userCode, USER_CODE_TOKEN_TYPE);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		String authorizationUri = request.getRequestURL().toString();
		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(clientId, principal)
				.authorizationUri(authorizationUri)
				.state(authorization.getAttribute(OAuth2ParameterNames.STATE))
				.scopes(authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME))
				.consent(false)
				.build();
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
