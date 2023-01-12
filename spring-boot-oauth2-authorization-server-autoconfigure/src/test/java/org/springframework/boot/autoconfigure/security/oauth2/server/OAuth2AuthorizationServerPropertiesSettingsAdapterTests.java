/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.boot.autoconfigure.security.oauth2.server;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2AuthorizationServerPropertiesRegistrationAdapter}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2AuthorizationServerPropertiesSettingsAdapterTests {

	@Test
	void getAuthorizationServerSettingsWhenValidParametersShouldAdapt() {
		OAuth2AuthorizationServerProperties.AuthorizationServerSettings authorizationServerSettings =
				createAuthorizationServerSettings();
		OAuth2AuthorizationServerProperties properties = new OAuth2AuthorizationServerProperties();
		properties.setSettings(authorizationServerSettings);

		AuthorizationServerSettings settings = OAuth2AuthorizationServerPropertiesSettingsAdapter
				.getAuthorizationServerSettings(properties);
		assertThat(settings.getIssuer()).isEqualTo("https://example.com");
		assertThat(settings.getAuthorizationEndpoint()).isEqualTo("/authorize");
		assertThat(settings.getTokenEndpoint()).isEqualTo("/token");
		assertThat(settings.getJwkSetEndpoint()).isEqualTo("/jwks");
		assertThat(settings.getTokenRevocationEndpoint()).isEqualTo("/revoke");
		assertThat(settings.getTokenIntrospectionEndpoint()).isEqualTo("/introspect");
		assertThat(settings.getOidcClientRegistrationEndpoint()).isEqualTo("/register");
		assertThat(settings.getOidcUserInfoEndpoint()).isEqualTo("/user");
	}

	private OAuth2AuthorizationServerProperties.AuthorizationServerSettings createAuthorizationServerSettings() {
		OAuth2AuthorizationServerProperties.AuthorizationServerSettings settings =
				new OAuth2AuthorizationServerProperties.AuthorizationServerSettings();
		settings.setIssuer("https://example.com");
		settings.setAuthorizationEndpoint("/authorize");
		settings.setTokenEndpoint("/token");
		settings.setJwkSetEndpoint("/jwks");
		settings.setTokenRevocationEndpoint("/revoke");
		settings.setTokenIntrospectionEndpoint("/introspect");
		settings.setOidcClientRegistrationEndpoint("/register");
		settings.setOidcUserInfoEndpoint("/user");
		return settings;
	}

}
