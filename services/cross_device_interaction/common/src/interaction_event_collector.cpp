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

#include "interaction_event_collector.h"

#include "event_manager_adapter.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_INTERACTION_EVENT_COLLECTOR

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

void InteractionEventCollector::SetHostUserId(UserId hostUserId)
{
    hostUserId_ = hostUserId;
}

void InteractionEventCollector::SetHostDeviceKey(const DeviceKey &hostDeviceKey)
{
    hostDeviceKey_ = hostDeviceKey;
}

void InteractionEventCollector::SetCompanionUserId(UserId companionUserId)
{
    companionUserId_ = companionUserId;
}

void InteractionEventCollector::SetCompanionDeviceKey(const DeviceKey &companionDeviceKey)
{
    companionDeviceKey_ = companionDeviceKey;
}

void InteractionEventCollector::SetConnectionName(const std::string &connectionName)
{
    connectionName_ = connectionName;
}

void InteractionEventCollector::SetScheduleId(ScheduleId scheduleId)
{
    scheduleId_ = scheduleId;
}

void InteractionEventCollector::SetTriggerReason(const std::string &triggerReason)
{
    triggerReason_ = triggerReason;
}

void InteractionEventCollector::SetTemplateIdList(const std::vector<TemplateId> &templateIdList)
{
    templateIdList_ = templateIdList;
}

void InteractionEventCollector::SetCallerUserId(UserId callerUserId)
{
    callerUserId_ = callerUserId;
}

namespace {
constexpr const char *KEY_CALLER_USER_ID = "callerUserId";
constexpr const char *KEY_ATL = "ATL";
constexpr const char *KEY_BINDING_ID = "bindingId";
constexpr const char *KEY_CONTEXT_ID = "contextId";
constexpr const char *KEY_SUCCESS_AUTH_TYPE = "successAuthType";
constexpr const char *KEY_ALGORITHM_LIST = "algorithmList";
constexpr const char *KEY_SELECTED_ALGORITHM = "selectedAlgorithm";
constexpr const char *KEY_ESL = "ESL";
constexpr const char *KEY_PROTOCOL_ID_LIST = "protocolIdList";
constexpr const char *KEY_CAPABILITY_LIST = "capabilityList";
constexpr const char *KEY_SELECTED_PROTOCOL_ID_LIST = "selectedProtocolIdList";
constexpr const char *KEY_SECURE_PROTOCOL_ID = "secureProtocolId";
constexpr const char *KEY_TEMPLATE_AUTH_RESULT = "templateAuthResult";
constexpr const char *KEY_SUCCESS_TEMPLATE_ID = "successTemplateId";
constexpr const char *KEY_LOG_TRACE = "logTrace";
constexpr const char *KEY_TIME_TRACE = "timeTrace";

} // namespace

void InteractionEventCollector::SetAtl(Atl atl)
{
    atl_ = atl;
}

void InteractionEventCollector::SetBindingId(BindingId bindingId)
{
    bindingId_ = bindingId;
}

void InteractionEventCollector::SetContextId(uint64_t contextId)
{
    contextId_ = contextId;
}

void InteractionEventCollector::SetSuccessAuthType(int32_t authType)
{
    successAuthType_ = authType;
}

void InteractionEventCollector::SetAlgorithmList(const std::vector<uint16_t> &algorithmList)
{
    algorithmList_ = algorithmList;
}

void InteractionEventCollector::SetSelectedAlgorithm(uint16_t algorithm)
{
    selectedAlgorithm_ = algorithm;
}

void InteractionEventCollector::SetEsl(int32_t esl)
{
    esl_ = esl;
}

void InteractionEventCollector::SetProtocolIdList(const std::vector<uint16_t> &protocolIdList)
{
    protocolIdList_ = protocolIdList;
}

void InteractionEventCollector::SetCapabilityList(const std::vector<uint16_t> &capabilityList)
{
    capabilityList_ = capabilityList;
}

void InteractionEventCollector::SetSelectedProtocolIdList(const std::vector<uint16_t> &selectedProtocolIdList)
{
    selectedProtocolIdList_ = selectedProtocolIdList;
}

void InteractionEventCollector::SetSecureProtocolId(uint16_t secureProtocolId)
{
    secureProtocolId_ = secureProtocolId;
}

void InteractionEventCollector::AddTemplateAuthResult(TemplateId templateId, ResultCode result)
{
    if (!templateAuthResult_.empty()) {
        templateAuthResult_.append(",");
    }
    templateAuthResult_.append(ToHexString(templateId))
        .append(":")
        .append(std::to_string(static_cast<int32_t>(result)));
}

void InteractionEventCollector::SetSuccessTemplateId(TemplateId templateId)
{
    successTemplateId_ = templateId;
}

void InteractionEventCollector::Start()
{
    tracer_.Start();
}

void InteractionEventCollector::Mark(StageId id)
{
    tracer_.Mark(id);
}

void InteractionEventCollector::EnterWait(StageId id)
{
    tracer_.EnterWait(id);
}

void InteractionEventCollector::ExitWait(StageId id)
{
    tracer_.ExitWait(id);
}

void InteractionEventCollector::BuildExtraInfoStep1(std::ostringstream &oss) const
{
    if (atl_.has_value()) {
        oss << ";" << KEY_ATL << ":" << *atl_;
    }
    if (bindingId_.has_value()) {
        oss << ";" << KEY_BINDING_ID << ":" << ToHexString(*bindingId_);
    }
    if (contextId_.has_value()) {
        oss << ";" << KEY_CONTEXT_ID << ":" << ToHexString(*contextId_);
    }
    if (successAuthType_.has_value()) {
        oss << ";" << KEY_SUCCESS_AUTH_TYPE << ":" << *successAuthType_;
    }
    if (algorithmList_.has_value()) {
        oss << ";" << KEY_ALGORITHM_LIST << ":" << GetVectorString<uint16_t>(*algorithmList_);
    }
    if (selectedAlgorithm_.has_value()) {
        oss << ";" << KEY_SELECTED_ALGORITHM << ":" << *selectedAlgorithm_;
    }
    if (callerUserId_.has_value()) {
        oss << ";" << KEY_CALLER_USER_ID << ":" << *callerUserId_;
    }
}

void InteractionEventCollector::BuildExtraInfoStep2(std::ostringstream &oss) const
{
    if (esl_.has_value()) {
        oss << ";" << KEY_ESL << ":" << *esl_;
    }
    if (protocolIdList_.has_value()) {
        oss << ";" << KEY_PROTOCOL_ID_LIST << ":" << GetVectorString<uint16_t>(*protocolIdList_);
    }
    if (capabilityList_.has_value()) {
        oss << ";" << KEY_CAPABILITY_LIST << ":" << GetVectorString<uint16_t>(*capabilityList_);
    }
    if (selectedProtocolIdList_.has_value()) {
        oss << ";" << KEY_SELECTED_PROTOCOL_ID_LIST << ":" << GetVectorString<uint16_t>(*selectedProtocolIdList_);
    }
    if (secureProtocolId_.has_value()) {
        oss << ";" << KEY_SECURE_PROTOCOL_ID << ":" << *secureProtocolId_;
    }
    if (!templateAuthResult_.empty()) {
        oss << ";" << KEY_TEMPLATE_AUTH_RESULT << ":" << templateAuthResult_;
    }
    if (successTemplateId_.has_value()) {
        oss << ";" << KEY_SUCCESS_TEMPLATE_ID << ":" << ToHexString(*successTemplateId_);
    }
    if (!logTrace_.empty()) {
        oss << ";" << KEY_LOG_TRACE << ":" << logTrace_;
    }
    std::string timeTrace = tracer_.ExportTrace();
    if (!timeTrace.empty()) {
        oss << ";" << KEY_TIME_TRACE << ":" << timeTrace;
    }
}

std::string InteractionEventCollector::GetExtraInfo() const
{
    std::ostringstream oss;
    BuildExtraInfoStep1(oss);
    BuildExtraInfoStep2(oss);
    std::string result = oss.str();
    static constexpr size_t PREFIX_LEN = 1; // ";" prefix length
    if (result.size() >= PREFIX_LEN && result[0] == ';') {
        result.erase(0, PREFIX_LEN);
    }
    return result;
}

void InteractionEventCollector::Report(ResultCode result)
{
    if (reported_) {
        return;
    }
    reported_ = true;
    result_ = result;
    tracer_.Finish();
    logTrace_ = LogTracer::GetInstance().ExportAsString();
    IAM_LOGI("requestType: %{public}s, logTrace: %{public}s", requestType_.c_str(), logTrace_.c_str());
    ReportInteractionEvent(*this);
}

std::optional<uint64_t> InteractionEventCollector::GetTotalTime() const
{
    if (!tracer_.Started()) {
        return std::nullopt;
    }
    return tracer_.TotalMs();
}

std::optional<uint64_t> InteractionEventCollector::GetLocalTime() const
{
    if (!tracer_.Started()) {
        return std::nullopt;
    }
    return tracer_.LocalMs();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
