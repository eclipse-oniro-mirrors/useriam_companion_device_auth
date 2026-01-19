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

#ifndef COMPANION_DEVICE_AUTH_DEVICE_MANAGER_ADAPTER_IMPL_H
#define COMPANION_DEVICE_AUTH_DEVICE_MANAGER_ADAPTER_IMPL_H

#include "device_manager_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class DeviceManagerAdapterImpl : public IDeviceManagerAdapter {
public:
    static std::shared_ptr<DeviceManagerAdapterImpl> Create();

    ~DeviceManagerAdapterImpl() override = default;

    bool InitDeviceManager() override;
    void UnInitDeviceManager() override;
    std::optional<std::string> GetUdidByNetworkId(const std::string &networkId) override;
    bool QueryTrustedDevices(std::vector<DmDeviceInfo> &deviceList) override;
    bool RegisterDevStatusCallback(std::shared_ptr<DmDeviceStatusCallback> callback) override;
    void UnRegisterDevStatusCallback(std::shared_ptr<DmDeviceStatusCallback> callback) override;

private:
    DeviceManagerAdapterImpl() = default;
    bool Initialize();
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_DEVICE_MANAGER_ADAPTER_IMPL_H
