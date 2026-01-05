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

#ifndef COMPANION_DEVICE_AUTH_HOST_ISSUE_TOKEN_REQUEST_H
#define COMPANION_DEVICE_AUTH_HOST_ISSUE_TOKEN_REQUEST_H

#include <memory>
#include <optional>
#include <vector>

#include "companion_manager.h"
#include "outbound_request.h"
#include "security_agent.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class HostIssueTokenRequest : public OutboundRequest, public std::enable_shared_from_this<HostIssueTokenRequest> {
public:
    HostIssueTokenRequest(UserId hostUserId, TemplateId templateId, const std::vector<uint8_t> &fwkUnlockMsg);
    ~HostIssueTokenRequest() override = default;

    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const override;

#ifndef ENABLE_TEST
protected:
#endif
    bool OnStart(ErrorGuard &errorGuard) override;
    void OnConnected() override;
    void CompleteWithError(ResultCode result) override;
    std::weak_ptr<OutboundRequest> GetWeakPtr() override;

#ifndef ENABLE_TEST
private:
#endif
    void HostPreIssueToken();
    bool SendPreIssueTokenRequest(const std::vector<uint8_t> &preIssueTokenRequest);
    bool SendIssueTokenRequest(const std::vector<uint8_t> &issueTokenRequest);
    void HandlePreIssueTokenReply(const Attributes &message);
    void HandleIssueTokenReply(const Attributes &message);
    bool EnsureCompanionAuthMaintainActive(const DeviceKey &deviceKey, ErrorGuard &errorGuard);
    void HandlePeerDeviceStatusChanged(const std::vector<DeviceStatus> &deviceStatusList);
    void CompleteWithSuccess();

    UserId hostUserId_ = INVALID_USER_ID;
    UserId companionUserId_ = INVALID_USER_ID;
    TemplateId templateId_ = 0;
    std::vector<uint8_t> fwkUnlockMsg_;
    bool needCancelIssueToken_ = false;
    SecureProtocolId secureProtocolId_ = SecureProtocolId::DEFAULT;
    std::unique_ptr<Subscription> deviceStatusSubscription_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_ISSUE_TOKEN_REQUEST_H
