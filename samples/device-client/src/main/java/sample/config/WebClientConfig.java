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

import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import sample.repository.DeviceRepository;
import sample.web.authentication.DeviceCodeOAuth2AuthorizedClientProvider;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author Steve Riesenberg
 * @since 0.3.0
 */
@Configuration
public class WebClientConfig {

	@Bean
	public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
		ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
				new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		return WebClient.builder()
				.apply(oauth2Client.oauth2Configuration())
				.build();
	}

	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			DeviceRepository deviceRepository) {

		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.provider(new DeviceCodeOAuth2AuthorizedClientProvider())
						.authorizationCode()
						.refreshToken()
						.build();
		DefaultOAuth2AuthorizedClientManager authorizedClientManager =
				new DefaultOAuth2AuthorizedClientManager(
						clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
		authorizedClientManager.setContextAttributesMapper(deviceCodeContextAttributesMapper(deviceRepository));

		return authorizedClientManager;
	}

	private Function<OAuth2AuthorizeRequest, Map<String, Object>> deviceCodeContextAttributesMapper(
			DeviceRepository deviceRepository) {

		return authorizeRequest -> {
			HttpServletRequest request = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
			Assert.notNull(request, "request cannot be null");

			// Look up device code via user code
			String userCode = request.getParameter("code");
			String deviceCode = null;
			if (userCode != null) {
				deviceCode = deviceRepository.findDeviceCodeByUserCode(userCode);
				if (deviceCode == null) {
					OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
					throw new OAuth2AuthorizationException(oauth2Error);
				}
			}

			return (deviceCode != null) ? Collections.singletonMap("device_code", deviceCode) : null;
		};
	}

}
