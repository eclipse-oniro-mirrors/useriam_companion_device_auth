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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_DEVICE_MANAGER_H
#define COMPANION_DEVICE_AUTH_COMPANION_DEVICE_MANAGER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using OnCompanionDeviceStatusChange = std::function<void(const std::vector<CompanionStatus> &companionStatusList)>;

struct BeginAddCompanionParams {
    RequestId requestId;
    ScheduleId scheduleId;
    DeviceKey hostDeviceKey;
    DeviceKey companionDeviceKey;
    std::vector<uint8_t> fwkMsg;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> initKeyNegotiationReply;
};

struct EndAddCompanionInput {
    RequestId requestId;
    PersistedCompanionStatus companionStatus;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> addHostBindingReply;
};

struct EndAddCompanionOutput {
    std::vector<uint8_t> fwkMsg;
    std::vector<uint8_t> tokenData;
    Atl atl;
};

class ICompanionManager : public NoCopyable {
public:
    virtual ~ICompanionManager() = default;

    virtual void Initialize() = 0;
    virtual std::optional<CompanionStatus> GetCompanionStatus(TemplateId templateId) = 0;
    virtual std::optional<CompanionStatus> GetCompanionStatus(UserId hostUserId,
        const DeviceKey &companionDeviceKey) = 0;
    virtual std::vector<CompanionStatus> GetAllCompanionStatus() = 0;

    virtual std::unique_ptr<Subscription> SubscribeCompanionDeviceStatusChange(
        OnCompanionDeviceStatusChange &&callback) = 0;
    virtual void UnsubscribeCompanionDeviceStatusChange(SubscribeId subscriptionId) = 0;

    virtual ResultCode BeginAddCompanion(const BeginAddCompanionParams &params,
        std::vector<uint8_t> &outAddHostBindingRequest) = 0;
    virtual ResultCode EndAddCompanion(const EndAddCompanionInput &input, EndAddCompanionOutput &output) = 0;
    virtual ResultCode RemoveCompanion(TemplateId templateId) = 0;

    virtual ResultCode UpdateCompanionStatus(TemplateId templateId, const std::string &deviceName,
        const std::string &deviceUserName) = 0;
    virtual ResultCode UpdateCompanionEnabledBusinessIds(TemplateId templateId,
        const std::vector<BusinessId> &enabledBusinessIds) = 0;
    virtual bool SetCompanionTokenAtl(TemplateId templateId, std::optional<Atl> atl) = 0;

    virtual ResultCode UpdateToken(TemplateId templateId, const std::vector<uint8_t> &fwkMsg,
        bool &needRedistribute) = 0;

    virtual ResultCode HandleCompanionCheckFail(TemplateId templateId) = 0;

    virtual void StartIssueTokenRequests(const std::vector<TemplateId> &templateIds,
        const std::vector<uint8_t> &fwkUnlockMsg) = 0;

    virtual void NotifyCompanionStatusChange() = 0;
    virtual void HandleRemoveHostBindingComplete(TemplateId templateId) = 0;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_DEVICE_MANAGER_H
