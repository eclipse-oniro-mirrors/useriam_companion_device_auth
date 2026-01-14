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

#ifndef COMPANION_DEVICE_AUTH_SOFT_BUS_ADAPTER_H
#define COMPANION_DEVICE_AUTH_SOFT_BUS_ADAPTER_H

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "service_common.h"
#include "socket.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SocketId = int32_t;

class ISoftBusSocketCallback {
public:
    virtual ~ISoftBusSocketCallback() = default;

    virtual void HandleBind(int32_t socketId, const std::string &peerNetworkId) = 0;
    virtual void HandleBytes(int32_t socketId, const void *data, uint32_t dataLen) = 0;
    virtual void HandleShutdown(int32_t socketId, int32_t reason) = 0;
    virtual void HandleError(int32_t socketId, int32_t errorCode) = 0;

#ifndef ENABLE_TEST
protected:
#endif
    ISoftBusSocketCallback() = default;
};

class ISoftBusAdapter : public NoCopyable {
public:
    virtual ~ISoftBusAdapter() = default;

    virtual void RegisterCallback(std::shared_ptr<ISoftBusSocketCallback> callback) = 0;
    virtual std::optional<SocketId> CreateServerSocket() = 0;
    virtual std::optional<SocketId> CreateClientSocket(const std::string &networkId) = 0;
    virtual bool SendBytes(int32_t socketId, const std::vector<uint8_t> &data) = 0;
    virtual void ShutdownSocket(int32_t socketId) = 0;

#ifndef ENABLE_TEST
protected:
#endif
    ISoftBusAdapter() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SOFT_BUS_ADAPTER_H
