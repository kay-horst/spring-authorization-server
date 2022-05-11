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
package sample.repository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * @author Steve Riesenberg
 * @since 0.3.0
 */
@Component
public class DeviceRepository {

	private final Map<String, String> deviceCodes = new ConcurrentHashMap<>();

	public Optional<String> findDeviceCodeByUserCode(String userCode) {
		return Optional.ofNullable(this.deviceCodes.get(userCode));
	}

	public void save(String userCode, String deviceCode) {
		this.deviceCodes.put(userCode, deviceCode);
	}

}
