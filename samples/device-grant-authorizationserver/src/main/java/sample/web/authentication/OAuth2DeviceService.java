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

import org.springframework.lang.Nullable;

/**
 * Implementations of this interface are responsible for managing devices for the
 * OAuth 2.0 Device Authorization Grant.
 *
 * @author Steve Riesenberg
 * @since 0.3.0
 * @see OAuth2Device
 */
public interface OAuth2DeviceService {

	/**
	 * Saves the {@link OAuth2Device}.
	 *
	 * @param device the {@link OAuth2Device}
	 */
	void save(OAuth2Device device);

	/**
	 * Removes the {@link OAuth2Device}.
	 *
	 * @param device the {@link OAuth2Device}
	 */
	void remove(OAuth2Device device);

	/**
	 * Returns the {@link OAuth2Device} identified by the provided {@code deviceCode}
	 * or {@code null} if not found.
	 *
	 * @param deviceCode the device code
	 * @return the {@link OAuth2Device} if found, otherwise {@code null}
	 */
	@Nullable
	OAuth2Device findByDeviceCode(String deviceCode);

	/**
	 * Returns the {@link OAuth2Device} identified by the provided {@code userCode}
	 * or {@code null} if not found.
	 *
	 * @param userCode the user code
	 * @return the {@link OAuth2Device} if found, otherwise {@code null}
	 */
	@Nullable
	OAuth2Device findByUserCode(String userCode);

}
