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

#ifndef COMPANION_DEVICE_AUTH_HOST_ADD_COMPANION_REQUEST_H
#define COMPANION_DEVICE_AUTH_HOST_ADD_COMPANION_REQUEST_H

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "add_companion_message.h"
#include "companion_manager.h"
#include "error_guard.h"
#include "outbound_request.h"
#include "security_agent.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class HostAddCompanionRequest : public std::enable_shared_from_this<HostAddCompanionRequest>, public OutboundRequest {
public:
    HostAddCompanionRequest(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg, uint32_t tokenId,
        FwkResultCallback &&requestCallback);
    ~HostAddCompanionRequest() override = default;

    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const override;

protected:
    bool OnStart(ErrorGuard &errorGuard) override;
    void OnConnected() override;
    void CompleteWithError(ResultCode result) override;
    void CompleteWithSuccess();
    std::weak_ptr<OutboundRequest> GetWeakPtr() override;

private:
    void HandleDeviceSelectResult(const std::vector<DeviceKey> &selectedDevices);
    bool BeginAddCompanion(const InitKeyNegotiationReply &reply, std::vector<uint8_t> &addHostBindingRequest,
        ErrorGuard &errorGuard);
    void HandleInitKeyNegotiationReply(const Attributes &reply);
    void HandleBeginAddHostBindingReply(const Attributes &reply);
    void HandleEndAddHostBindingReply(const Attributes &reply);
    bool EndAddCompanion(const BeginAddHostBindingReply &reply, std::vector<uint8_t> &fwkMsg);
    bool SendEndAddHostBindingMsg(ResultCode result);
    void InvokeCallback(ResultCode result, const std::vector<uint8_t> &extraInfo);

    std::vector<uint8_t> fwkMsg_;
    uint32_t tokenId_ = 0;
    std::vector<uint8_t> addCompanionFwkMsg_ {};
    std::vector<uint8_t> pendingTokenData_ {}; // Token data for EndAddHostBinding message
    TemplateId templateId_ {};                 // TemplateId after successful binding
    Atl tokenAtl_ = 0;                         // ATL level of token
    bool needCancelCompanionAdd_ = false;
    bool needCancelIssueToken_ = false;
    FwkResultCallback requestCallback_;
    bool callbackInvoked_ = false;
    DeviceKey hostDeviceKey_ {};
    SecureProtocolId secureProtocolId_ = SecureProtocolId::INVALID;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_ADD_COMPANION_REQUEST_H
