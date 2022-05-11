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

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} for the OAuth 2.0 Device Authorization Grant,
 * which handles the processing of the OAuth 2.0 Device Authorization Request.
 *
 * @author Steve Riesenberg
 * @since 0.3.0
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628">OAuth 2.0 Device Authorization Grant</a>
 */
public final class OAuth2DeviceAuthorizationEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for device authorization requests.
	 */
	public static final String DEFAULT_DEVICE_AUTHORIZATION_ENDPOINT_URI = "/oauth2/device/device_authorization";

	private final AuthenticationManager authenticationManager;
	private final RequestMatcher deviceAuthorizationEndpointMatcher;
	private final HttpMessageConverter<Object> deviceAuthorizationHttpResponseConverter;
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter;
	private AuthenticationConverter authenticationConverter;
	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendAuthorizationResponse;
	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2DeviceAuthorizationEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_DEVICE_AUTHORIZATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param deviceAuthorizationEndpointUri the endpoint {@code URI} for device authorization requests
	 */
	public OAuth2DeviceAuthorizationEndpointFilter(AuthenticationManager authenticationManager, String deviceAuthorizationEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(deviceAuthorizationEndpointUri, "authorizationEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.deviceAuthorizationEndpointMatcher = new AntPathRequestMatcher(DEFAULT_DEVICE_AUTHORIZATION_ENDPOINT_URI, HttpMethod.POST.name());
		this.deviceAuthorizationHttpResponseConverter = new MappingJackson2HttpMessageConverter(); // TODO: Create custom converter?
		this.errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();
		this.authenticationConverter = new OAuth2DeviceAuthorizationRequestAuthenticationConverter();
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract a Device Authorization Request from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2DeviceAuthorizationRequestAuthenticationToken} used for authenticating the request.
	 *
	 * @param authenticationConverter the {@link AuthenticationConverter} used when attempting to extract a DeviceAuthorization Request from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 * and returning the Device Authorization Response.
	 *
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.deviceAuthorizationEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			OAuth2DeviceAuthorizationRequestAuthenticationToken deviceAuthorizationRequestAuthenticationToken =
					(OAuth2DeviceAuthorizationRequestAuthenticationToken) this.authenticationConverter.convert(request);

			OAuth2DeviceAuthorizationRequestAuthenticationToken deviceAuthorizationRequestAuthenticationTokenResult =
					(OAuth2DeviceAuthorizationRequestAuthenticationToken) this.authenticationManager.authenticate(deviceAuthorizationRequestAuthenticationToken);

			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, deviceAuthorizationRequestAuthenticationTokenResult);
		} catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	private void sendAuthorizationResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {

		OAuth2DeviceAuthorizationRequestAuthenticationToken deviceAuthorizationRequestAuthenticationToken =
				(OAuth2DeviceAuthorizationRequestAuthenticationToken) authentication;

		Map<String, Object> parameters = new LinkedHashMap<>();
		parameters.put("device_code", deviceAuthorizationRequestAuthenticationToken.getDeviceCode());
		parameters.put("user_code", deviceAuthorizationRequestAuthenticationToken.getUserCode());
		parameters.put("verification_uri", deviceAuthorizationRequestAuthenticationToken.getVerificationUri());
		parameters.put("verification_uri_complete", deviceAuthorizationRequestAuthenticationToken.getVerificationUriComplete());
		parameters.put("expires_in", deviceAuthorizationRequestAuthenticationToken.getExpiresIn());
		parameters.put("interval", deviceAuthorizationRequestAuthenticationToken.getInterval());

		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.deviceAuthorizationHttpResponseConverter.write(parameters, null, httpResponse);
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authenticationException) throws IOException {

		OAuth2Error error = ((OAuth2AuthenticationException) authenticationException).getError();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}
}


