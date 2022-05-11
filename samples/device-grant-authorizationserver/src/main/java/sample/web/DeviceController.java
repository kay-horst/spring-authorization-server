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

import sample.web.authentication.OAuth2Device;
import sample.web.authentication.OAuth2DeviceService;

import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author Steve Riesenberg
 * @since 0.3.0
 */
@Controller
public class DeviceController {

	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	private final OAuth2AuthorizationService authorizationService;
	private final OAuth2DeviceService deviceService;

	public DeviceController(OAuth2AuthorizationService authorizationService, OAuth2DeviceService deviceService) {
		this.authorizationService = authorizationService;
		this.deviceService = deviceService;
	}

	@GetMapping("/activate")
	public String activate(@RequestParam(name = "code", required = false) String activationCode, HttpServletRequest request) {
		if (activationCode != null) {
			return submitCode(activationCode, request);
		}
		return "activate";
	}

	@PostMapping("/activate")
	public String submitCode(@RequestParam(name = "code") String activationCode, HttpServletRequest request) {
		OAuth2Device device = this.deviceService.findByUserCode(activationCode);
		String authorizationUri = UriComponentsBuilder.fromHttpRequest(new ServletServerHttpRequest(request))
				.replacePath("/oauth2/device/authorize")
				.queryParam(OAuth2ParameterNames.CLIENT_ID, device.getClientId())
				.queryParam(OAuth2ParameterNames.SCOPE, StringUtils.collectionToDelimitedString(device.getScopes(), " "))
				.queryParam(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue())
				.build()
				.toUriString();
		return "redirect:" + authorizationUri;
	}

	@GetMapping("/activated")
	public String activated() {
		return "activated";
	}

}
