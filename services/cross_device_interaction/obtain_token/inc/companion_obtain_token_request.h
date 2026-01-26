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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_OBTAIN_TOKEN_REQUEST_H
#define COMPANION_DEVICE_AUTH_COMPANION_OBTAIN_TOKEN_REQUEST_H

#include <memory>
#include <vector>

#include "host_binding_manager.h"
#include "obtain_token_message.h"
#include "outbound_request.h"
#include "security_agent.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionObtainTokenRequest : public std::enable_shared_from_this<CompanionObtainTokenRequest>,
                                    public OutboundRequest {
public:
    CompanionObtainTokenRequest(const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg);
    ~CompanionObtainTokenRequest() override = default;

    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const override;

protected:
    bool OnStart(ErrorGuard &errorGuard) override;
    void OnConnected() override;
    void CompleteWithError(ResultCode result) override;
    std::weak_ptr<OutboundRequest> GetWeakPtr() override;

private:
    bool SendPreObtainTokenRequest();
    void HandlePreObtainTokenReply(const Attributes &reply);
    bool CompanionBeginObtainToken(const PreObtainTokenReply &preObtainTokenReply);
    bool SendObtainTokenRequest(const std::vector<uint8_t> &obtainTokenRequest);
    void HandleObtainTokenReply(const Attributes &reply);
    bool CompanionEndObtainToken(const ObtainTokenReply &obtainTokenReply);
    void CompleteWithSuccess();
    void HandleAuthMaintainActiveChanged(bool isActive);

    DeviceKey companionDeviceKey_;
    DeviceKey hostDeviceKey_;
    std::vector<uint8_t> fwkUnlockMsg_;
    SecureProtocolId secureProtocolId_ = SecureProtocolId::INVALID;
    BindingId bindingId_ = 0;
    bool needCancelObtainToken_ = false;
    std::unique_ptr<Subscription> localDeviceStatusSubscription_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_OBTAIN_TOKEN_REQUEST_H
