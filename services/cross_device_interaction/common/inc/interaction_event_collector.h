/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_INTERACTION_EVENT_COLLECTOR_H
#define COMPANION_DEVICE_AUTH_INTERACTION_EVENT_COLLECTOR_H

#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "common_defines.h"
#include "iam_log_tracer.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class InteractionEventCollector {
public:
    explicit InteractionEventCollector(const std::string &requestType) : requestType_(requestType)
    {
    }
    ~InteractionEventCollector() = default;

    void SetHostUserId(UserId hostUserId);
    void SetHostDeviceKey(const DeviceKey &hostDeviceKey);
    void SetCompanionUserId(UserId companionUserId);
    void SetCompanionDeviceKey(const DeviceKey &companionDeviceKey);
    void SetConnectionName(const std::string &connectionName);
    void SetScheduleId(ScheduleId scheduleId);
    void SetTriggerReason(const std::string &triggerReason);
    void SetTemplateIdList(const std::vector<TemplateId> &templateIdList);

    void SetAtl(Atl atl);
    void SetBindingId(BindingId bindingId);
    void SetContextId(uint64_t contextId);
    void SetSuccessAuthType(int32_t authType);
    void SetAlgorithmList(const std::vector<uint16_t> &algorithmList);
    void SetSelectedAlgorithm(uint16_t algorithm);
    void SetEsl(int32_t esl);
    void SetProtocolIdList(const std::vector<uint16_t> &protocolIdList);
    void SetCapabilityList(const std::vector<uint16_t> &capabilityList);
    void SetSelectedProtocolIdList(const std::vector<uint16_t> &selectedProtocolIdList);
    void SetSecureProtocolId(uint16_t secureProtocolId);
    void AddTemplateAuthResult(TemplateId templateId, ResultCode result);
    void SetSuccessTemplateId(TemplateId templateId);

    void Report(ResultCode result);

    const std::string &GetRequestType() const
    {
        return requestType_;
    }
    ResultCode GetResult() const
    {
        return result_;
    }
    const std::optional<UserId> &GetHostUserId() const
    {
        return hostUserId_;
    }
    const std::optional<DeviceKey> &GetHostDeviceKey() const
    {
        return hostDeviceKey_;
    }
    const std::optional<UserId> &GetCompanionUserId() const
    {
        return companionUserId_;
    }
    const std::optional<DeviceKey> &GetCompanionDeviceKey() const
    {
        return companionDeviceKey_;
    }
    const std::optional<std::string> &GetConnectionName() const
    {
        return connectionName_;
    }
    const std::optional<ScheduleId> &GetScheduleId() const
    {
        return scheduleId_;
    }
    const std::optional<std::string> &GetTriggerReason() const
    {
        return triggerReason_;
    }
    const std::optional<std::vector<TemplateId>> &GetTemplateIdList() const
    {
        return templateIdList_;
    }
    std::string GetExtraInfo() const;

private:
    void BuildExtraInfoStep1(std::ostringstream &oss) const;
    void BuildExtraInfoStep2(std::ostringstream &oss) const;

    std::string requestType_;
    ResultCode result_ = ResultCode::SUCCESS;
    std::optional<UserId> hostUserId_;
    std::optional<DeviceKey> hostDeviceKey_;
    std::optional<UserId> companionUserId_;
    std::optional<DeviceKey> companionDeviceKey_;
    std::optional<std::string> connectionName_;
    std::optional<ScheduleId> scheduleId_;
    std::optional<std::string> triggerReason_;
    std::optional<std::vector<TemplateId>> templateIdList_;
    std::optional<Atl> atl_;
    std::optional<BindingId> bindingId_;
    std::optional<uint64_t> contextId_;
    std::optional<int32_t> successAuthType_;
    std::optional<std::vector<uint16_t>> algorithmList_;
    std::optional<uint16_t> selectedAlgorithm_;
    std::optional<int32_t> esl_;
    std::optional<std::vector<uint16_t>> protocolIdList_;
    std::optional<std::vector<uint16_t>> capabilityList_;
    std::optional<std::vector<uint16_t>> selectedProtocolIdList_;
    std::optional<uint16_t> secureProtocolId_;
    std::string templateAuthResult_;
    std::optional<TemplateId> successTemplateId_;
    std::string logTrace_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_INTERACTION_EVENT_COLLECTOR_H
