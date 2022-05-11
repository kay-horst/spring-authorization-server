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

import java.time.Instant;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * @author Steve Riesenberg
 * @since 0.3.0
 */
public final class OAuth2DeviceTokenRequestAuthenticationConverter implements AuthenticationConverter {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
			"anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private static final String DEVICE_CODE = "device_code";
	private static final String AUTHORIZATION_PENDING = "authorization_pending";
	private static final String EXPIRED_TOKEN = "expired_token";

	private final OAuth2DeviceService deviceService;

	public OAuth2DeviceTokenRequestAuthenticationConverter(OAuth2DeviceService deviceService) {
		this.deviceService = deviceService;
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		// grant_type (REQUIRED)
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (!OAuth2Device.GRANT_TYPE.getValue().equals(grantType)) {
			return null;
		}

		// client_id (REQUIRED)
		String clientId = getParameter(request, OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId)) {
			throwError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_ID);
		}

		// device_code (REQUIRED)
		String deviceCode = request.getParameter(DEVICE_CODE);
		if (!StringUtils.hasText(deviceCode)) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, DEVICE_CODE);
		}

		/*
		 * TODO: These checks should be in an AuthenticationProvider, but are here so we can re-use the existing
		 *       OAuth2AuthorizationCodeAuthenticationProvider for the token endpoint.
		 */

		// Client authentication is REQUIRED
		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}

		if (!OAuth2ClientAuthenticationToken.class.isAssignableFrom(principal.getClass())
				|| !principal.isAuthenticated()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		// Check whether authorization has been granted
		OAuth2Device device = this.deviceService.findByDeviceCode(deviceCode);
		String authorizationCode = (device != null) ? device.getAuthorizationCode() : null;
		if (authorizationCode == null) {
			throw new OAuth2AuthenticationException(AUTHORIZATION_PENDING);
		}

		// Check whether device authorization request has expired
		if (device.getExpiresAt().isBefore(Instant.now())) {
			throw new OAuth2AuthenticationException(EXPIRED_TOKEN);
		}

		return new OAuth2AuthorizationCodeAuthenticationToken(authorizationCode, principal, null, null);
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
