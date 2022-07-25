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

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author Steve Riesenberg
 * @since 0.4.0
 */
@Controller
public class DeviceController {

	private final OAuth2AuthorizationService authorizationService;
	private final RegisteredClientRepository registeredClientRepository;

	public DeviceController(OAuth2AuthorizationService authorizationService, RegisteredClientRepository registeredClientRepository) {
		this.authorizationService = authorizationService;
		this.registeredClientRepository = registeredClientRepository;
	}

	@GetMapping("/activate")
	public String activate(@RequestParam(name = "code", required = false) String userCode, HttpServletRequest request) {
		if (userCode != null) {
			return submitCode(userCode, request);
		}
		return "activate";
	}

	@PostMapping("/activate")
	public String submitCode(@RequestParam(name = "code") String userCode, HttpServletRequest request) {
		OAuth2Authorization authorization = this.authorizationService.findByToken(userCode, new OAuth2TokenType("user_code"));
		Assert.notNull(authorization, "authorization cannot be null");

		RegisteredClient registeredClient = this.registeredClientRepository.findById(
				authorization.getRegisteredClientId());
		Assert.notNull(registeredClient, "registeredClient cannot be null");

		String authorizationUri = UriComponentsBuilder.fromHttpRequest(new ServletServerHttpRequest(request))
				.replacePath("/oauth2/device/authorize")
				.queryParam(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.build()
				.toUriString();
		return "redirect:" + authorizationUri;
	}

	@GetMapping("/activated")
	public String activated() {
		return "activated";
	}

}
