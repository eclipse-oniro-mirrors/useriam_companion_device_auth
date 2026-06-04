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

#include <nlohmann/json.hpp>

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
        const std::string &additionalInfo, FwkResultCallback &&requestCallback);
    ~HostAddCompanionRequest() override = default;

    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(const IRequest &newRequest, uint32_t subsequentSameTypeCount) const override;

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
    std::optional<PersistedCompanionStatus> BuildPersistedCompanionStatus(const DeviceStatus &deviceStatus);
    EndAddCompanionInput BuildEndAddCompanionInput(const PersistedCompanionStatus &companionStatus,
        const DeviceStatus &deviceStatus, const std::vector<uint8_t> &addHostBindingReply);
    void ProcessEndAddCompanionOutput(const EndAddCompanionOutput &output, std::vector<uint8_t> &fwkMsg);
    void ParseAdditionalInfo();
    std::vector<BusinessId> ParseBusinessIdsFromJson(const nlohmann::json &businessIdsArray);
    void ValidateAndFilterBusinessIds(const std::vector<BusinessId> &parsedIds);
    std::optional<DeviceKey> QueryLocalDeviceKey();
    std::optional<SecureProtocolId> QuerySecureProtocolId(const DeviceKey &peerDeviceKey);
    ResultCode CallSecurityAgentGetInitKeyNegotiationRequest(std::vector<uint8_t> &initKeyNegotiationRequest);
    ResultCode SendInitKeyNegotiationRequest(const std::vector<uint8_t> &initKeyNegotiationRequest);
    BeginAddCompanionParams BuildBeginAddCompanionParams(const InitKeyNegotiationReply &reply) const;

    std::vector<uint8_t> fwkMsg_;
    uint32_t tokenId_ = 0;
    std::string additionalInfo_; // Store additionalInfo for parsing
    std::vector<uint8_t> addCompanionFwkMsg_ {};
    std::vector<uint8_t> pendingTokenData_ {}; // Token data for EndAddHostBinding message
    Atl tokenAuthAtl_ = 0;                     // ATL level of token auth
    bool needCancelCompanionAdd_ = false;
    bool enrollmentSucceeded_ = false;
    FwkResultCallback requestCallback_;
    DeviceKey hostDeviceKey_ {};
    SecureProtocolId secureProtocolId_ = SecureProtocolId::INVALID;
    std::vector<BusinessId> enabledBusinessIdsFromAdditionalInfo_; // Parsed from additionalInfo
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_ADD_COMPANION_REQUEST_H
