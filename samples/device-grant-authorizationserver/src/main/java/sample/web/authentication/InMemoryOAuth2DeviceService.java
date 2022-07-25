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
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.util.Assert;

/**
 * An {@link OAuth2DeviceService} that stores {@link OAuth2Device}'s in-memory.
 *
 * <p>
 * <b>NOTE:</b> This implementation should ONLY be used during development/testing.
 *
 * @author Steve Riesenberg
 * @since 0.4.0
 * @see OAuth2DeviceService
 */
public class InMemoryOAuth2DeviceService implements OAuth2DeviceService {
	private static final int DEFAULT_MAX_DEVICES = 100;

	private final Map<String, OAuth2Device> devices;

	public InMemoryOAuth2DeviceService() {
		this(DEFAULT_MAX_DEVICES);
	}

	InMemoryOAuth2DeviceService(int maxDevices) {
		this.devices = Collections.synchronizedMap(new MaxSizeHashMap<>(maxDevices));
	}

	@Override
	public void save(OAuth2Device device) {
		Assert.notNull(device, "device cannot be null");
		this.devices.put(device.getUserCode(), device);
	}

	@Override
	public void remove(OAuth2Device device) {
		Assert.notNull(device, "device cannot be null");
		this.devices.remove(device.getUserCode());
	}

	@Override
	public OAuth2Device findByDeviceCode(String deviceCode) {
		Assert.hasText(deviceCode, "deviceCode cannot be empty");
		for (OAuth2Device device : this.devices.values()) {
			if (deviceCode.equals(device.getDeviceCode())) {
				return device;
			}
		}
		return null;
	}

	@Override
	public OAuth2Device findByUserCode(String userCode) {
		Assert.hasText(userCode, "userCode cannot be empty");
		return this.devices.get(userCode);
	}

	private static final class MaxSizeHashMap<K, V> extends LinkedHashMap<K, V> {
		private final int maxSize;

		private MaxSizeHashMap(int maxSize) {
			this.maxSize = maxSize;
		}

		@Override
		protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
			return size() > this.maxSize;
		}
	}
}
