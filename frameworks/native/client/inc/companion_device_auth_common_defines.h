/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file companion_device_auth_common_defines.h
 *
 * @brief Some common defines in companion_device_auth.
 */

#ifndef COMPANION_DEVICE_AUTH_COMMON_DEFINES_H
#define COMPANION_DEVICE_AUTH_COMMON_DEFINES_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
/**
 * @brief Key information that uniquely identifies a companion device.
 */
struct ClientDeviceKey {
    /* Identifier type describing how the device is referenced. */
    int32_t deviceIdType;
    /* Device identifier content such as the Unified Device Identifier or a vendor-specific value. */
    std::string deviceId;
    /* Local user identifier on the device. */
    int32_t deviceUserId;
};

/**
 * @brief Companion device metadata and runtime status for template coordination.
 */
struct ClientDeviceStatus {
    /* Device key referencing the device. */
    ClientDeviceKey deviceKey;
    /* Display name of the user on the device. */
    std::string deviceUserName;
    /* Model information reported by the device. */
    std::string deviceModelInfo;
    /* Friendly name assigned to the device. */
    std::string deviceName;
    /* Whether the device is currently reachable. */
    bool isOnline;
    /* Business identifiers currently enabled on the device. */
    std::vector<int32_t> supportedBusinessIds;
};

/**
 * @brief Template metadata managed by the companion device authentication service.
 */
struct ClientTemplateStatus {
    /* Identifier of the template encoded as binary data. */
    uint64_t templateId;
    /* Whether the template's status has been confirmed. */
    bool isConfirmed;
    /* Whether the template is still valid and can be used for authentication. */
    bool isValid;
    /* Local user identifier associated with the template. */
    int32_t localUserId;
    /* Time when the template was added. */
    int64_t addedTime;
    /* Business identifiers enabled for this template. */
    std::vector<int32_t> enabledBusinessIds;
    /* Device status associated with this template. */
    ClientDeviceStatus deviceStatus;
};

/**
 * @brief Result returned by the device selection callback.
 */
struct ClientDeviceSelectResult {
    /** Device keys used to identify a companion device. */
    std::vector<ClientDeviceKey> deviceKeys;
    /** Optional context information related to the device selection process. */
    std::optional<std::vector<uint8_t>> selectionContext;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // COMPANION_DEVICE_AUTH_COMMON_DEFINES_H