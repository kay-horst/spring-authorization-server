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
package org.springframework.boot.autoconfigure.security.oauth2.server.servlet;

import org.springframework.boot.autoconfigure.security.ConditionalOnDefaultWebSecurity;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.server.OAuth2AuthorizationServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * {@link Configuration @Configuration} for OAuth2 authorization server support.
 *
 * @author Steve Riesenberg
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OAuth2AuthorizationServerProperties.class)
@ConditionalOnDefaultWebSecurity
class OAuth2AuthorizationServerWebSecurityConfiguration {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		// @formatter:off
		http
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
			.exceptionHandling((exceptions) -> exceptions
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			);
		// @formatter:on
		return http.build();
	}

	@Bean
	@Order(SecurityProperties.BASIC_AUTH_ORDER)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			.formLogin(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}

}
