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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * @author Steve Riesenberg
 * @since 0.4.0
 */
public final class OAuth2DeviceAuthorizationRequestAuthenticationConverter implements AuthenticationConverter {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
			"anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	@Override
	public Authentication convert(HttpServletRequest request) {
		String authorizationUri = request.getRequestURL().toString();

		// client_id (REQUIRED)
		String clientId = getParameter(request, OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId)) {
			throwError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_ID);
		}

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}

		// scope (OPTIONAL)
		Set<String> scopes = null;
		String scope = getParameter(request, OAuth2ParameterNames.SCOPE);
		if (StringUtils.hasText(scope)) {
			scopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		// @formatter:off
		return OAuth2DeviceAuthorizationRequestAuthenticationToken.with(clientId, principal)
				.authorizationUri(authorizationUri)
				.scopes(scopes)
				.build();
		// @formatter:on
	}

	private static String getParameter(HttpServletRequest request, String parameterName) {
		String[] parameterValues = request.getParameterValues(parameterName);
		String parameterValue = null;
		if (parameterValues != null) {
			if (parameterValues.length != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, parameterName);
			}
			parameterValue = parameterValues[0];
		}
		return parameterValue;
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}
}
