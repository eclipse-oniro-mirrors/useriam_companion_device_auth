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

#ifndef COMPANION_DEVICE_AUTH_HOST_OBTAIN_TOKEN_REQUEST_H
#define COMPANION_DEVICE_AUTH_HOST_OBTAIN_TOKEN_REQUEST_H

#include <memory>

#include "companion_manager.h"
#include "inbound_request.h"
#include "obtain_token_message.h"
#include "security_agent.h"
#include "service_common.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class HostObtainTokenRequest : public std::enable_shared_from_this<HostObtainTokenRequest>, public InboundRequest {
public:
    HostObtainTokenRequest(const std::string &connectionName, const Attributes &request, OnMessageReply replyCallback,
        const DeviceKey &companionDeviceKey);
    ~HostObtainTokenRequest() override = default;

    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const override;

protected:
    bool OnStart(ErrorGuard &errorGuard) override;
    void CompleteWithError(ResultCode result) override;
    void CompleteWithSuccess();
    std::weak_ptr<InboundRequest> GetWeakPtr() override;

private:
    bool ParsePreObtainTokenRequest(ErrorGuard &errorGuard);
    bool ProcessPreObtainToken(std::vector<uint8_t> &preObtainTokenReply);
    void SendPreObtainTokenReply(ResultCode result, const std::vector<uint8_t> &preObtainTokenReply);
    void HandleObtainTokenMessage(const Attributes &request, OnMessageReply &onMessageReply);
    bool HandleHostProcessObtainToken(const ObtainTokenRequest &request, std::vector<uint8_t> &obtainTokenReply);
    bool EnsureCompanionAuthMaintainActive(const DeviceKey &deviceKey, ErrorGuard &errorGuard);
    void HandlePeerDeviceStatusChanged(const std::vector<DeviceStatus> &deviceStatusList);

    Attributes request_;
    OnMessageReply preObtainTokenReplyCallback_;
    std::unique_ptr<Subscription> obtainTokenSubscription_;
    std::unique_ptr<Subscription> deviceStatusSubscription_;

    UserId hostUserId_ = INVALID_USER_ID;
    UserId companionUserId_ = INVALID_USER_ID;
    TemplateId templateId_ = 0;
    SecureProtocolId secureProtocolId_ = SecureProtocolId::INVALID;
    bool needCancelObtainToken_ = false;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_OBTAIN_TOKEN_REQUEST_H
