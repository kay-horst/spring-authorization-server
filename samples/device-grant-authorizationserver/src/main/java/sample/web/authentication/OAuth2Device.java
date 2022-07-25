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

import java.io.Serializable;
import java.time.Instant;
import java.util.Set;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.Version;
import org.springframework.util.Assert;

/**
 * @author Steve Riesenberg
 * @since 0.4.0
 */
public class OAuth2Device implements Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	static final AuthorizationGrantType GRANT_TYPE = new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:device_code");

	private String id;
	private String clientId;
	private Set<String> scopes;
	private String deviceCode;
	private String userCode;
	private String authorizationCode;
	private Instant issuedAt;
	private Instant expiresAt;

	public String getId() {
		return id;
	}

	public String getClientId() {
		return clientId;
	}

	public Set<String> getScopes() {
		return scopes;
	}

	public String getDeviceCode() {
		return deviceCode;
	}

	public String getUserCode() {
		return userCode;
	}

	public String getAuthorizationCode() {
		return authorizationCode;
	}

	public Instant getIssuedAt() {
		return issuedAt;
	}

	public Instant getExpiresAt() {
		return expiresAt;
	}

	public static Builder withClientId(String clientId) {
		Assert.notNull(clientId, "clientId cannot be null");
		return new Builder(clientId);
	}

	public static Builder with(OAuth2Device device) {
		Assert.notNull(device, "device cannot be null");
		return new Builder(device);
	}

	/**
	 * A builder for {@link OAuth2Device}.
	 */
	public static final class Builder {
		private String id;
		private String clientId;
		private Set<String> scopes;
		private String deviceCode;
		private String userCode;
		private String authorizationCode;
		private Instant issuedAt;
		private Instant expiresAt;

		Builder(String clientId) {
			this.clientId = clientId;
		}

		Builder(OAuth2Device device) {
			this.id = device.id;
			this.clientId = device.clientId;
			this.scopes = device.scopes;
			this.deviceCode = device.deviceCode;
			this.userCode = device.userCode;
			this.authorizationCode = device.authorizationCode;
			this.issuedAt = device.issuedAt;
			this.expiresAt = device.expiresAt;
		}

		public Builder id(String id) {
			this.id = id;
			return this;
		}

		public Builder scopes(Set<String> scopes) {
			this.scopes = scopes;
			return this;
		}

		public Builder deviceCode(String deviceCode) {
			this.deviceCode = deviceCode;
			return this;
		}

		public Builder userCode(String userCode) {
			this.userCode = userCode;
			return this;
		}

		public Builder authorizationCode(String authorizationCode) {
			this.authorizationCode = authorizationCode;
			return this;
		}

		public Builder issuedAt(Instant issuedAt) {
			this.issuedAt = issuedAt;
			return this;
		}

		public Builder expiresAt(Instant expiresAt) {
			this.expiresAt = expiresAt;
			return this;
		}

		public OAuth2Device build() {
			Assert.hasText(this.deviceCode, "deviceCode cannot be empty");
			Assert.hasText(this.userCode, "userCode cannot be empty");

			OAuth2Device device = new OAuth2Device();
			device.id = this.id;
			device.clientId = this.clientId;
			device.scopes = this.scopes;
			device.deviceCode = this.deviceCode;
			device.userCode = this.userCode;
			device.authorizationCode = authorizationCode;
			device.issuedAt = this.issuedAt;
			device.expiresAt = this.expiresAt;

			return device;
		}
	}
}
