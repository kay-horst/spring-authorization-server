/*
 * Copyright 2020-2023 the original author or authors.
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

import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.server.OAuth2AuthorizationServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.server.OAuth2AuthorizationServerPropertiesRegistrationAdapter;
import org.springframework.boot.autoconfigure.security.oauth2.server.OAuth2AuthorizationServerPropertiesSettingsAdapter;
import org.springframework.boot.autoconfigure.security.oauth2.server.RegisteredClientsConfiguredCondition;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * {@link Configuration @Configuration} for OAuth2 authorization server support.
 *
 * @author Steve Riesenberg
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OAuth2AuthorizationServerProperties.class)
class OAuth2AuthorizationServerPropertiesConfiguration {

	@Bean
	@ConditionalOnMissingBean
	@Conditional(RegisteredClientsConfiguredCondition.class)
	RegisteredClientRepository registeredClientRepository(OAuth2AuthorizationServerProperties properties) {
		List<RegisteredClient> registeredClients = OAuth2AuthorizationServerPropertiesRegistrationAdapter
				.getRegisteredClients(properties);
		return new InMemoryRegisteredClientRepository(registeredClients);
	}

	@Bean
	@ConditionalOnMissingBean
	AuthorizationServerSettings authorizationServerSettings(OAuth2AuthorizationServerProperties properties) {
		return OAuth2AuthorizationServerPropertiesSettingsAdapter.getAuthorizationServerSettings(properties);
	}

}
