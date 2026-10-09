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

#ifndef COMPANION_DEVICE_AUTH_DEVICE_MANAGER_ADAPTER_H
#define COMPANION_DEVICE_AUTH_DEVICE_MANAGER_ADAPTER_H

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "device_manager.h"
#include "nocopyable.h"

#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using DistributedHardware::DmDeviceInfo;
using DmDeviceStatusCallback = DistributedHardware::DeviceStatusCallback;

class IDeviceManagerAdapter : public NoCopyable {
public:
    virtual ~IDeviceManagerAdapter() = default;

    virtual bool InitDeviceManager() = 0;
    virtual void UnInitDeviceManager() = 0;
    virtual std::optional<std::string> GetUdidByNetworkId(const std::string &networkId) = 0;
    virtual bool QueryTrustedDevices(std::vector<DmDeviceInfo> &deviceList) = 0;
    virtual bool RegisterDevStatusCallback(const std::shared_ptr<DmDeviceStatusCallback> &callback) = 0;
    virtual void UnRegisterDevStatusCallback(const std::shared_ptr<DmDeviceStatusCallback> &callback) = 0;

protected:
    IDeviceManagerAdapter() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_DEVICE_MANAGER_ADAPTER_H
