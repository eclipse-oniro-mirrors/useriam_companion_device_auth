/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMPANION_DEVICE_AUTH_HOST_BINDING_MANAGER_H
#define COMPANION_DEVICE_AUTH_HOST_BINDING_MANAGER_H

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "nocopyable.h"

#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class IHostBindingManager : public NoCopyable {
public:
    virtual ~IHostBindingManager() = default;

    virtual std::optional<HostBindingStatus> GetHostBindingStatus(BindingId bindingId) = 0;
    virtual std::optional<HostBindingStatus> GetHostBindingStatus(UserId companionUserId,
        const DeviceKey &hostDeviceKey) = 0;

    virtual ResultCode BeginAddHostBinding(RequestId requestId, UserId companionUserId,
        SecureProtocolId secureProtocolId, const std::vector<uint8_t> &addHostBindingRequest,
        std::vector<uint8_t> &outAddHostBindingReply) = 0;
    virtual ResultCode EndAddHostBinding(RequestId requestId, ResultCode resultCode,
        const std::vector<uint8_t> &tokenData = {}) = 0;
    virtual ResultCode RemoveHostBinding(UserId companionUserId, const DeviceKey &hostDeviceKey) = 0;
    virtual bool SetHostBindingTokenValid(BindingId bindingId, bool isTokenValid) = 0;

    virtual void StartObtainTokenRequests(UserId userId, const std::vector<uint8_t> &fwkUnlockMsg) = 0;
    virtual void RevokeTokens(UserId userId) = 0;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_BINDING_MANAGER_H
