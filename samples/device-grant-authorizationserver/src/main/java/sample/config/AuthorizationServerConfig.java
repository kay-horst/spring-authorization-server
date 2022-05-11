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
package sample.config;

import sample.web.authentication.InMemoryOAuth2DeviceService;
import sample.web.authentication.OAuth2DeviceAuthorizationEndpointConfigurer;
import sample.web.authentication.OAuth2DeviceService;
import sample.web.authentication.OAuth2DeviceTokenRequestAuthenticationConverter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author Steve Riesenberg
 * @since 0.3.0
 */
@Configuration
public class AuthorizationServerConfig {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		// @formatter:off
		http
			.exceptionHandling(exceptions ->
				exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			);
		// @formatter:on
		return http.build();
	}

	// @formatter:off
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 5)
	public SecurityFilterChain deviceAuthorizationSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2DeviceAuthorizationEndpointConfigurer deviceAuthorizationEndpointConfigurer =
				new OAuth2DeviceAuthorizationEndpointConfigurer();

		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer<>();
		authorizationServerConfigurer
			.authorizationEndpoint(authorizationEndpoint ->
				authorizationEndpoint
					.authorizationResponseHandler(new SimpleUrlAuthenticationSuccessHandler("/activated"))
			)
			.tokenEndpoint(tokenEndpoint ->
				tokenEndpoint
					.accessTokenRequestConverter(new OAuth2DeviceTokenRequestAuthenticationConverter(deviceService()))
			);

		RequestMatcher requestMatcher = new OrRequestMatcher(
			deviceAuthorizationEndpointConfigurer.getRequestMatcher(),
			authorizationServerConfigurer.getEndpointsMatcher()
		);

		http
			.requestMatcher(requestMatcher)
			.authorizeRequests(authorizeRequests ->
				authorizeRequests.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(requestMatcher))
			.exceptionHandling(exceptions ->
				exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			);
		http.apply(deviceAuthorizationEndpointConfigurer);
		http.apply(authorizationServerConfigurer)
			.providerSettings(ProviderSettings.builder()
				.authorizationEndpoint("/oauth2/device/authorize")
				.tokenEndpoint("/oauth2/device/token")
				.build()
			);

		return http.build();
	}
	// @formatter:on

	@Bean
	public OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService() {
		return new InMemoryOAuth2AuthorizationConsentService();
	}

	@Bean
	public OAuth2DeviceService deviceService() {
		return new InMemoryOAuth2DeviceService();
	}

}
