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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_ISSUE_TOKEN_REQUEST_H
#define COMPANION_DEVICE_AUTH_COMPANION_ISSUE_TOKEN_REQUEST_H

#include <memory>
#include <optional>
#include <vector>

#include "host_binding_manager.h"
#include "inbound_request.h"
#include "issue_token_message.h"
#include "security_agent.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionIssueTokenRequest : public std::enable_shared_from_this<CompanionIssueTokenRequest>,
                                   public InboundRequest {
public:
    CompanionIssueTokenRequest(const std::string &connectionName, const Attributes &request,
        OnMessageReply replyCallback, const DeviceKey &hostDeviceKey);
    ~CompanionIssueTokenRequest() override = default;

    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const override;

protected:
    bool OnStart(ErrorGuard &errorGuard) override;
    std::weak_ptr<InboundRequest> GetWeakPtr() override;
    void CompleteWithError(ResultCode result) override;
    void CompleteWithSuccess();

private:
    void HandleIssueTokenMessage(const Attributes &request, OnMessageReply &onMessageReply);
    bool SecureAgentCompanionIssueToken(const std::vector<uint8_t> &issueTokenRequest,
        std::vector<uint8_t> &issueTokenReply);
    bool CompanionPreIssueToken(std::vector<uint8_t> &preIssueTokenReply);
    void SendPreIssueTokenReply(ResultCode result, const std::vector<uint8_t> &preIssueTokenReply);
    void SendErrorReply(ResultCode result);
    void HandleAuthMaintainActiveChanged(bool isActive);

    Attributes request_;
    int32_t companionUserId_ = 0;
    std::vector<uint8_t> preIssueTokenRequest_;
    SecureProtocolId secureProtocolId_ = SecureProtocolId::INVALID;
    BindingId bindingId_ = 0;
    bool needCancelIssueToken_ = false;
    OnMessageReply preIssueTokenReplyCallback_;
    std::unique_ptr<Subscription> issueTokenSubscription_;
    std::unique_ptr<Subscription> localDeviceStatusSubscription_;
    std::optional<MessageType> activeMsgType_;
    OnMessageReply issueReplyCallback_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_ISSUE_TOKEN_REQUEST_H
