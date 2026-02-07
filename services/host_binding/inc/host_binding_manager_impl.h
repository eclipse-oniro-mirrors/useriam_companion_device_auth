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

#ifndef COMPANION_DEVICE_AUTH_HOST_BINDING_MANAGER_IMPL_H
#define COMPANION_DEVICE_AUTH_HOST_BINDING_MANAGER_IMPL_H

#include <functional>
#include <memory>
#include <vector>

#include "host_binding.h"
#include "host_binding_manager.h"
#include "security_agent.h"
#include "service_common.h"
#include "singleton.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class HostBindingManagerImpl : public std::enable_shared_from_this<HostBindingManagerImpl>, public IHostBindingManager {
public:
    static std::shared_ptr<HostBindingManagerImpl> Create();

    ~HostBindingManagerImpl() override = default;

    std::optional<HostBindingStatus> GetHostBindingStatus(BindingId bindingId) override;
    std::optional<HostBindingStatus> GetHostBindingStatus(UserId companionUserId,
        const DeviceKey &hostDeviceKey) override;

    ResultCode BeginAddHostBinding(RequestId requestId, UserId companionUserId, SecureProtocolId secureProtocolId,
        const std::vector<uint8_t> &addHostBindingRequest, std::vector<uint8_t> &outAddHostBindingReply) override;

    ResultCode EndAddHostBinding(RequestId requestId, ResultCode resultCode,
        const std::vector<uint8_t> &tokenData = {}) override;

    ResultCode RemoveHostBinding(UserId companionUserId, const DeviceKey &hostDeviceKey) override;

    bool SetHostBindingTokenValid(BindingId bindingId, bool isTokenValid) override;

    void StartObtainTokenRequests(UserId userId, const std::vector<uint8_t> &fwkUnlockMsg) override;
    void RevokeTokens(UserId userId) override;

private:
    HostBindingManagerImpl() = default;
    bool Initialize();
    void OnActiveUserIdChanged(UserId userId);

    std::vector<HostBindingStatus> GetAllHostBindingStatus();

    std::shared_ptr<HostBinding> FindBindingById(BindingId bindingId);
    std::shared_ptr<HostBinding> FindBindingByDeviceUser(UserId userId, const DeviceKey &deviceKey);

    ResultCode AddBindingInternal(const std::shared_ptr<HostBinding> &binding);
    ResultCode RemoveBindingInternal(BindingId bindingId);

    UserId activeUserId_ { INVALID_USER_ID };
    std::vector<std::shared_ptr<HostBinding>> bindings_;

    std::unique_ptr<Subscription> activeUserIdSubscription_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_BINDING_MANAGER_IMPL_H
