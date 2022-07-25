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
package sample.web;

import java.util.Map;
import java.util.UUID;

import sample.repository.DeviceRepository;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Steve Riesenberg
 * @since 0.3.0
 */
@Controller
public class DeviceController {
	private static final ParameterizedTypeReference<Map<String, Object>> TYPE_REFERENCE =
			new ParameterizedTypeReference<Map<String, Object>>() {
			};

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final WebClient webClient;

	private final String messagesBaseUri;

	private final DeviceRepository deviceRepository;

	public DeviceController(
			ClientRegistrationRepository clientRegistrationRepository,
			WebClient webClient,
			DeviceRepository deviceRepository,
			@Value("${messages.base-uri}") String messagesBaseUri) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.webClient = webClient;
		this.deviceRepository = deviceRepository;
		this.messagesBaseUri = messagesBaseUri;
	}

	@GetMapping("/")
	public String home(Authentication authentication) {
		if (authentication == null) {
			// @formatter:off
			User randomIdentityForDevice = new User(
					UUID.randomUUID().toString(), "(null)", AuthorityUtils.createAuthorityList("DEVICE"));
			UsernamePasswordAuthenticationToken authenticationToken =
					new UsernamePasswordAuthenticationToken(
							randomIdentityForDevice, null, randomIdentityForDevice.getAuthorities());
			SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
			securityContext.setAuthentication(authenticationToken);
			SecurityContextHolder.setContext(securityContext);
			// @formatter:on
		}
		return "redirect:/authorize";
	}

	@GetMapping("/authorize")
	public String authorize(Model model) {
		ClientRegistration clientRegistration =
				this.clientRegistrationRepository.findByRegistrationId("messaging-client-device-grant");

		MultiValueMap<String, String> requestParameters = new LinkedMultiValueMap<>();
		requestParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		requestParameters.add(OAuth2ParameterNames.SCOPE, StringUtils.collectionToDelimitedString(
				clientRegistration.getScopes(), " "));

		// @formatter:off
		Map<String, Object> responseParameters =
				this.webClient.post()
						.uri(clientRegistration.getProviderDetails().getAuthorizationUri())
						.headers(headers -> headers.setBasicAuth(clientRegistration.getClientId(),
								clientRegistration.getClientSecret()))
						.contentType(MediaType.APPLICATION_FORM_URLENCODED)
						.body(BodyInserters.fromFormData(requestParameters))
						.retrieve()
						.bodyToMono(TYPE_REFERENCE)
						.block();
		// @formatter:on

		Assert.notNull(responseParameters, "response cannot be null");
		String userCode = (String) responseParameters.get("user_code");
		String deviceCode = (String) responseParameters.get("device_code");
		this.deviceRepository.save(userCode, deviceCode);

		model.addAttribute("userCode", userCode);
		return "authorize";
	}

	@PostMapping("/authorize")
	public void requestAuthorization(
			// Also used by DefaultOAuth2AuthorizedClientManager#contextAttributesMapper, see SecurityConfig
			@RequestParam("code") String userCode,
			@RegisteredOAuth2AuthorizedClient("messaging-client-device-grant")
					OAuth2AuthorizedClient authorizedClient) {
		this.deviceRepository.remove(userCode);
		// This endpoint simply returns 200 OK when client is authorized
	}

	@GetMapping("/authorized")
	public String authorized(Model model,
			@RegisteredOAuth2AuthorizedClient("messaging-client-device-grant")
					OAuth2AuthorizedClient authorizedClient) {

		String[] messages = this.webClient.get()
				.uri(this.messagesBaseUri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		model.addAttribute("messages", messages);

		return "authorized";
	}

}
