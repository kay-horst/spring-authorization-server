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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.util.Assert;

/**
 * @author Steve Riesenberg
 * @since 0.4.0
 */
public final class InMemoryOAuth2DeviceAuthorizationService implements OAuth2AuthorizationService {

	private static final List<Class<? extends AbstractOAuth2Token>> DEVICE_TOKEN_TYPES =
			Collections.unmodifiableList(Arrays.asList(OAuth2DeviceCode.class, OAuth2UserCode.class));

	private final OAuth2AuthorizationService delegate = new InMemoryOAuth2AuthorizationService();

	private final Map<String, String> devices = new ConcurrentHashMap<>();

	@Override
	public OAuth2Authorization findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return this.delegate.findById(id);
	}

	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");
		if (this.devices.containsKey(token)) {
			return this.delegate.findById(this.devices.get(token));
		}
		return this.delegate.findByToken(token, tokenType);
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		for (Class<? extends AbstractOAuth2Token> tokenType : DEVICE_TOKEN_TYPES) {
			OAuth2Authorization.Token<? extends AbstractOAuth2Token> token = authorization.getToken(tokenType);
			if (token != null) {
				this.devices.put(token.getToken().getTokenValue(), authorization.getId());
			}
		}
		this.delegate.save(authorization);
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		this.devices.values().removeIf(id -> authorization.getId().equals(id));
		this.delegate.remove(authorization);
	}

}
