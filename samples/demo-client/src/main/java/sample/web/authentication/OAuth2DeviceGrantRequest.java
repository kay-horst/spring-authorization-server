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
package sample.web.authentication;

import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * @author Steve Riesenberg
 * @since 1.1
 */
public final class OAuth2DeviceGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

	private final String deviceCode;

	public OAuth2DeviceGrantRequest(ClientRegistration clientRegistration, String deviceCode) {
		super(AuthorizationGrantType.DEVICE_CODE, clientRegistration);
		Assert.hasText(deviceCode, "deviceCode cannot be empty");
		this.deviceCode = deviceCode;
	}

	public String getDeviceCode() {
		return this.deviceCode;
	}

}
