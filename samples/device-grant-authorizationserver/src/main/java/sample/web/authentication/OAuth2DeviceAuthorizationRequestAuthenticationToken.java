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

import java.util.Collections;
import java.util.Set;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.CollectionUtils;

/**
 * An {@link Authentication} implementation for the OAuth 2.0 Device Authorization Request
 * used in the Device Authorization Grant.
 *
 * @author Steve Riesenberg
 * @since 0.3.0
 * @see OAuth2DeviceAuthorizationRequestAuthenticationProvider
 */
public final class OAuth2DeviceAuthorizationRequestAuthenticationToken extends AbstractAuthenticationToken {
	private String clientId;
	private Authentication principal;
	private String authorizationUri;
	private Set<String> scopes;
	private String deviceCode;
	private String userCode;
	private String verificationUri;
	private String verificationUriComplete;
	private Integer expiresIn;
	private Integer interval;

	private OAuth2DeviceAuthorizationRequestAuthenticationToken() {
		super(Collections.emptyList());
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	public String getClientId() {
		return this.clientId;
	}

	public String getAuthorizationUri() {
		return authorizationUri;
	}

	public Set<String> getScopes() {
		return this.scopes;
	}

	public String getDeviceCode() {
		return this.deviceCode;
	}

	public String getUserCode() {
		return this.userCode;
	}

	public String getVerificationUri() {
		return this.verificationUri;
	}

	public String getVerificationUriComplete() {
		return verificationUriComplete;
	}

	public Integer getExpiresIn() {
		return this.expiresIn;
	}

	public Integer getInterval() {
		return this.interval;
	}

	/**
	 * Returns a new {@link OAuth2DeviceAuthorizationRequestAuthenticationToken.Builder}, initialized with the given
	 * client identifier and {@code Principal} (Client).
	 *
	 * @param clientId the client identifier
	 * @param clientPrincipal the {@code Principal} (Client)
	 * @return the {@link OAuth2DeviceAuthorizationRequestAuthenticationToken.Builder}
	 */
	public static Builder with(@NonNull String clientId, @NonNull Authentication clientPrincipal) {
		return new Builder(clientId, clientPrincipal);
	}

	/**
	 * A builder for {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}.
	 */
	public static final class Builder {
		private final String clientId;
		private final Authentication principal;
		private String authorizationUri;
		private Set<String> scopes;
		private String deviceCode;
		private String userCode;
		private String verificationUri;
		private String verificationUriComplete;
		private Integer expiresIn;
		private Integer interval;

		public Builder(String clientId, Authentication principal) {
			this.clientId = clientId;
			this.principal = principal;
		}

		/**
		 * Sets the authorization URI.
		 *
		 * @param authorizationUri the authorization URI
		 * @return the {@link Builder}
		 */
		public Builder authorizationUri(String authorizationUri) {
			this.authorizationUri = authorizationUri;
			return this;
		}

		/**
		 * Set the scopes.
		 *
		 * @param scopes the scopes
		 * @return the {@link Builder}
		 */
		public Builder scopes(Set<String> scopes) {
			this.scopes = scopes;
			return this;
		}

		/**
		 * Set the device code.
		 *
		 * @param deviceCode the device code
		 * @return the {@link Builder}
		 */
		public Builder deviceCode(String deviceCode) {
			this.deviceCode = deviceCode;
			return this;
		}

		/**
		 * Set the user code.
		 *
		 * @param userCode the user code
		 * @return the {@link Builder}
		 */
		public Builder userCode(String userCode) {
			this.userCode = userCode;
			return this;
		}

		/**
		 * Set the end-user verification {@code URI}.
		 *
		 * @param verificationUri the end-user verification URI
		 * @return the {@link Builder}
		 */
		public Builder verificationUri(String verificationUri) {
			this.verificationUri = verificationUri;
			return this;
		}

		/**
		 * Set the complete end-user verification {@code URI}.
		 *
		 * @param verificationUriComplete the end-user verification URI
		 * @return the {@link Builder}
		 */
		public Builder verificationUriComplete(String verificationUriComplete) {
			this.verificationUriComplete = verificationUriComplete;
			return this;
		}

		/**
		 * Set the lifetime in seconds of the device code and user code.
		 *
		 * @param expiresIn the lifetime in seconds of the device code and user code
		 * @return the {@link Builder}
		 */
		public Builder expiresIn(Integer expiresIn) {
			this.expiresIn = expiresIn;
			return this;
		}

		/**
		 * Set the minimum amount of time in seconds that the client should wait
		 * between polling requests to the token endpoint.
		 *
		 * @param interval the minimum amount of time in seconds that the client should wait
		 *                 between polling requests to the token endpoint
		 * @return the {@link Builder}
		 */
		public Builder interval(Integer interval) {
			this.interval = interval;
			return this;
		}

		/**
		 * Builds a new {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}.
		 *
		 * @return the {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
		 */
		public OAuth2DeviceAuthorizationRequestAuthenticationToken build() {
			OAuth2DeviceAuthorizationRequestAuthenticationToken authentication =
					new OAuth2DeviceAuthorizationRequestAuthenticationToken();
			authentication.clientId = this.clientId;
			authentication.principal = this.principal;
			authentication.authorizationUri = this.authorizationUri;
			authentication.scopes = Collections.unmodifiableSet(
					!CollectionUtils.isEmpty(this.scopes) ? this.scopes : Collections.emptySet());
			authentication.deviceCode = this.deviceCode;
			authentication.userCode = this.userCode;
			authentication.verificationUri = this.verificationUri;
			authentication.verificationUriComplete = verificationUriComplete;
			authentication.expiresIn = this.expiresIn;
			authentication.interval = this.interval;
			if (this.deviceCode != null && this.userCode != null) {
				authentication.setAuthenticated(true);
			}

			return authentication;
		}
	}
}
