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
 * @file available_device_status_callback.h
 *
 * @brief Callback invoked when available device status changes.
 */

#ifndef IAVAILABLE_DEVICE_STATUS_CALLBACK_H
#define IAVAILABLE_DEVICE_STATUS_CALLBACK_H

#include <vector>

#include "companion_device_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class IAvailableDeviceStatusCallback {
public:
    virtual ~IAvailableDeviceStatusCallback() = default;

    /**
     * @brief Callback invoked when available device status changes.
     *
     * @param deviceStatusList Status list of available devices.
     */
    virtual void OnAvailableDeviceStatusChange(const std::vector<ClientDeviceStatus> deviceStatusList) = 0;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAVAILABLE_DEVICE_STATUS_CALLBACK_H