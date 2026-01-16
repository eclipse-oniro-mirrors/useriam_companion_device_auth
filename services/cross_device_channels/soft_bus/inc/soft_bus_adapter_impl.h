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

#ifndef COMPANION_DEVICE_AUTH_SOFT_BUS_ADAPTER_IMPL_H
#define COMPANION_DEVICE_AUTH_SOFT_BUS_ADAPTER_IMPL_H

#include <map>
#include <memory>
#include <mutex>

#include "soft_bus_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SoftBusAdapterImpl : public ISoftBusAdapter {
public:
    SoftBusAdapterImpl() = default;
    ~SoftBusAdapterImpl() override = default;

    void RegisterCallback(std::shared_ptr<ISoftBusSocketCallback> callback) override;
    std::optional<SocketId> CreateServerSocket() override;
    std::optional<SocketId> CreateClientSocket(const std::string &connectionName,
        const std::string &networkId) override;
    bool SendBytes(int32_t socketId, const std::vector<uint8_t> &data) override;
    void ShutdownSocket(int32_t socketId) override;

private:
    std::shared_ptr<ISoftBusSocketCallback> callback_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SOFT_BUS_ADAPTER_IMPL_H
