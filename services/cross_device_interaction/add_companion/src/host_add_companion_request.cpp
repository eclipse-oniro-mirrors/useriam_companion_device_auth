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

#include "host_add_companion_request.h"

#include <algorithm>
#include <nlohmann/json.hpp>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "adapter_manager.h"
#include "add_companion_message.h"
#include "common_defines.h"
#include "common_message.h"
#include "companion_manager.h"
#include "error_guard.h"
#include "fwk_common.h"
#include "misc_manager.h"
#include "security_agent.h"
#include "service_converter.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostAddCompanionRequest::HostAddCompanionRequest(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg,
    uint32_t tokenId, const std::string &additionalInfo, FwkResultCallback &&requestCallback)
    : OutboundRequest(RequestType::HOST_ADD_COMPANION_REQUEST, scheduleId, DEFAULT_REQUEST_TIMEOUT_MS),
      fwkMsg_(fwkMsg),
      tokenId_(tokenId),
      additionalInfo_(additionalInfo),
      requestCallback_(std::move(requestCallback))
{
    ParseAdditionalInfo();
}

void HostAddCompanionRequest::ParseAdditionalInfo()
{
    if (additionalInfo_.empty()) {
        IAM_LOGI("%{public}s additionalInfo is empty", GetDescription());
        return;
    }

    IAM_LOGI("%{public}s parsing additionalInfo", GetDescription());
    try {
        auto json = nlohmann::json::parse(additionalInfo_);
        ENSURE_OR_RETURN_DESC(GetDescription(), json.is_object());

        auto it = json.find("enabled_business_ids");
        if (it == json.end() || !it->is_array()) {
            IAM_LOGI("%{public}s no enabled_business_ids array in additionalInfo", GetDescription());
            return;
        }

        std::vector<BusinessId> parsedIds = ParseBusinessIdsFromJson(*it);
        ValidateAndFilterBusinessIds(parsedIds);
    } catch (const nlohmann::json::exception &e) {
        IAM_LOGE("%{public}s failed to parse additionalInfo JSON: %{public}s", GetDescription(), e.what());
    }
}

std::vector<BusinessId> HostAddCompanionRequest::ParseBusinessIdsFromJson(const nlohmann::json &businessIdsArray)
{
    std::vector<BusinessId> parsedIds;
    for (const auto &item : businessIdsArray) {
        ENSURE_OR_CONTINUE_DESC(GetDescription(), item.is_number());
        BusinessId id = static_cast<BusinessId>(item.get<int32_t>());
        parsedIds.push_back(id);
    }
    return parsedIds;
}

void HostAddCompanionRequest::ValidateAndFilterBusinessIds(const std::vector<BusinessId> &parsedIds)
{
    auto deviceKey = GetPeerDeviceKey();
    if (!deviceKey.has_value()) {
        IAM_LOGW("%{public}s peer device key not available yet, keeping all parsed business IDs", GetDescription());
        enabledBusinessIdsFromAdditionalInfo_ = parsedIds;
        return;
    }

    auto deviceStatus = GetCrossDeviceCommManager().GetDeviceStatus(*deviceKey);
    if (!deviceStatus.has_value()) {
        IAM_LOGW("%{public}s failed to get device status, keeping all parsed business IDs", GetDescription());
        enabledBusinessIdsFromAdditionalInfo_ = parsedIds;
        return;
    }

    const auto &supportedIds = deviceStatus->supportedBusinessIds;
    for (const auto &id : parsedIds) {
        if (std::find(supportedIds.begin(), supportedIds.end(), id) != supportedIds.end()) {
            enabledBusinessIdsFromAdditionalInfo_.push_back(id);
            IAM_LOGI("%{public}s enabled business id: %{public}d is valid", GetDescription(), static_cast<int32_t>(id));
        } else {
            IAM_LOGE("%{public}s enabled business id: %{public}d is not supported, skipping", GetDescription(),
                static_cast<int32_t>(id));
        }
    }

    std::vector<int32_t> businessIdValues;
    for (const auto &id : enabledBusinessIdsFromAdditionalInfo_) {
        businessIdValues.push_back(static_cast<int32_t>(id));
    }
    IAM_LOGI("%{public}s parsed %{public}zu valid business IDs from additionalInfo: %{public}s", GetDescription(),
        enabledBusinessIdsFromAdditionalInfo_.size(), GetVectorString(businessIdValues).c_str());
}

bool HostAddCompanionRequest::OnStart([[maybe_unused]] ErrorGuard &errorGuard)
{
    GetCompanionManager().ReconcileWithSecurityAgent();

    bool selectorSet = GetMiscManager().GetDeviceDeviceSelectResult(tokenId_, SelectPurpose::SELECT_ADD_DEVICE,
        [weakSelf = weak_from_this()](const std::vector<DeviceKey> &selectedDevices,
            const std::optional<std::vector<uint8_t>> &_) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleDeviceSelectResult(selectedDevices);
        });
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), selectorSet, false);
    return true;
}

void HostAddCompanionRequest::HandleDeviceSelectResult(const std::vector<DeviceKey> &selectedDevices)
{
    IAM_LOGI("%{public}s HandleDeviceSelectResult", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    if (selectedDevices.size() != 1) {
        IAM_LOGE("%{public}s unexpected number of devices selected: %{public}zu", GetDescription(),
            selectedDevices.size());
        return;
    }

    SetPeerDeviceKey(selectedDevices[0]);

    if (!OpenConnection()) {
        IAM_LOGE("%{public}s OpenConnection failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

void HostAddCompanionRequest::OnConnected()
{
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto hostDeviceKeyOpt = QueryLocalDeviceKey();
    ENSURE_OR_RETURN_DESC(GetDescription(), hostDeviceKeyOpt.has_value());
    hostDeviceKey_ = hostDeviceKeyOpt.value();

    auto peerDeviceKeyOpt = GetPeerDeviceKey();
    ENSURE_OR_RETURN_DESC(GetDescription(), peerDeviceKeyOpt.has_value());
    auto secureProtocolIdOpt = QuerySecureProtocolId(peerDeviceKeyOpt.value());
    ENSURE_OR_RETURN_DESC(GetDescription(), secureProtocolIdOpt.has_value());
    secureProtocolId_ = *secureProtocolIdOpt;

    eventCollector_.SetHostUserId(hostDeviceKey_.deviceUserId);
    eventCollector_.SetCompanionDeviceKey(*peerDeviceKeyOpt);
    eventCollector_.SetConnectionName(GetConnectionName());
    eventCollector_.SetScheduleId(GetScheduleId());

    std::vector<uint8_t> initKeyNegotiationRequest;
    ResultCode ret = CallSecurityAgentGetInitKeyNegotiationRequest(initKeyNegotiationRequest);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CallSecurityAgentGetInitKeyNegotiationRequest failed", GetDescription());
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    ret = SendInitKeyNegotiationRequest(initKeyNegotiationRequest);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s SendInitKeyNegotiationRequest failed", GetDescription());
        errorGuard.UpdateErrorCode(ret);
        return;
    }
    errorGuard.Cancel();
}

std::optional<DeviceKey> HostAddCompanionRequest::QueryLocalDeviceKey()
{
    return GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
}

std::optional<SecureProtocolId> HostAddCompanionRequest::QuerySecureProtocolId(const DeviceKey &peerDeviceKey)
{
    return GetCrossDeviceCommManager().HostGetSecureProtocolId(peerDeviceKey);
}

ResultCode HostAddCompanionRequest::CallSecurityAgentGetInitKeyNegotiationRequest(
    std::vector<uint8_t> &initKeyNegotiationRequest)
{
    HostGetInitKeyNegotiationRequestInput input = {
        .requestId = GetRequestId(),
        .secureProtocolId = secureProtocolId_,
    };
    HostGetInitKeyNegotiationRequestOutput output = {};
    ResultCode ret = GetSecurityAgent().HostGetInitKeyNegotiationRequest(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostGetInitKeyNegotiationRequest failed ret=%{public}d", GetDescription(), ret);
        return ret;
    }
    needCancelCompanionAdd_ = true;
    eventCollector_.SetAlgorithmList(output.algorithmList);
    initKeyNegotiationRequest = std::move(output.initKeyNegotiationRequest);
    return ResultCode::SUCCESS;
}

ResultCode HostAddCompanionRequest::SendInitKeyNegotiationRequest(const std::vector<uint8_t> &initKeyNegotiationRequest)
{
    InitKeyNegotiationRequest initRequest { .hostDeviceKey = hostDeviceKey_, .extraInfo = initKeyNegotiationRequest };
    Attributes request = {};
    EncodeInitKeyNegotiationRequest(initRequest, request);
    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::INIT_KEY_NEGOTIATION,
        request, [weakSelf = weak_from_this()](const Attributes &reply) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleInitKeyNegotiationReply(reply);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return ResultCode::COMMUNICATION_ERROR;
    }
    return ResultCode::SUCCESS;
}

std::weak_ptr<OutboundRequest> HostAddCompanionRequest::GetWeakPtr()
{
    return weak_from_this();
}

void HostAddCompanionRequest::HandleInitKeyNegotiationReply(const Attributes &reply)
{
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto initReplyOpt = DecodeInitKeyNegotiationReply(reply);
    ENSURE_OR_RETURN_DESC(GetDescription(), initReplyOpt.has_value());

    const auto &initReply = *initReplyOpt;
    if (initReply.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s init key negotiation failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(initReply.result));
        errorGuard.UpdateErrorCode(initReply.result);
        return;
    }

    auto companionDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN_DESC(GetDescription(), companionDeviceKey.has_value());

    std::vector<uint8_t> addHostBindingRequest;
    bool ret = BeginAddCompanion(initReply, addHostBindingRequest, errorGuard);
    ENSURE_OR_RETURN_DESC(GetDescription(), ret);

    BeginAddHostBindingRequest beginRequest = { .companionUserId = companionDeviceKey->deviceUserId,
        .extraInfo = std::move(addHostBindingRequest) };
    Attributes request = {};
    EncodeBeginAddHostBindingRequest(beginRequest, request);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::BEGIN_ADD_HOST_BINDING,
        request, [weakSelf = weak_from_this()](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleBeginAddHostBindingReply(message);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

BeginAddCompanionParams HostAddCompanionRequest::BuildBeginAddCompanionParams(
    const InitKeyNegotiationReply &reply) const
{
    auto companionDeviceKey = GetPeerDeviceKey();
    BeginAddCompanionParams params = {};
    params.requestId = GetRequestId();
    params.scheduleId = GetScheduleId();
    params.hostDeviceKey = hostDeviceKey_;
    params.companionDeviceKey = *companionDeviceKey;
    params.fwkMsg = fwkMsg_;
    params.secureProtocolId = secureProtocolId_;
    params.initKeyNegotiationReply = reply.extraInfo;
    return params;
}

bool HostAddCompanionRequest::BeginAddCompanion(const InitKeyNegotiationReply &reply,
    std::vector<uint8_t> &addHostBindingRequest, ErrorGuard &errorGuard)
{
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), GetPeerDeviceKey().has_value(), false);
    auto params = BuildBeginAddCompanionParams(reply);
    uint16_t selectedAlgorithm;
    ResultCode ret = GetCompanionManager().BeginAddCompanion(params, addHostBindingRequest, selectedAlgorithm);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostBeginAddCompanion failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return false;
    }
    eventCollector_.SetSelectedAlgorithm(selectedAlgorithm);
    return true;
}

void HostAddCompanionRequest::HandleBeginAddHostBindingReply(const Attributes &reply)
{
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto beginReplyOpt = DecodeBeginAddHostBindingReply(reply);
    ENSURE_OR_RETURN_DESC(GetDescription(), beginReplyOpt.has_value());

    if (beginReplyOpt->result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s companion check failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(beginReplyOpt->result));
        errorGuard.UpdateErrorCode(beginReplyOpt->result);
        return;
    }

    bool handleRet = EndAddCompanion(*beginReplyOpt, addCompanionFwkMsg_);
    ENSURE_OR_RETURN_DESC(GetDescription(), handleRet);

    bool sendRet = SendEndAddHostBindingMsg(ResultCode::SUCCESS);
    if (!sendRet) {
        IAM_LOGE("%{public}s SendEndAddHostBindingMsg failed", GetDescription());
        return;
    }

    errorGuard.Cancel();
}

std::optional<PersistedCompanionStatus> HostAddCompanionRequest::BuildPersistedCompanionStatus(
    const DeviceStatus &deviceStatus)
{
    auto companionDeviceKey = GetPeerDeviceKey();
    if (!companionDeviceKey.has_value()) {
        return std::nullopt;
    }

    PersistedCompanionStatus companionStatus = {};
    companionStatus.hostUserId = hostDeviceKey_.deviceUserId;
    companionStatus.companionDeviceKey = *companionDeviceKey;
    companionStatus.deviceModelInfo = deviceStatus.deviceModelInfo;
    companionStatus.deviceUserName = deviceStatus.deviceUserName;
    companionStatus.deviceName = deviceStatus.deviceName;
    companionStatus.deviceType = deviceStatus.deviceType;
    companionStatus.isValid = true;
    return companionStatus;
}

EndAddCompanionInput HostAddCompanionRequest::BuildEndAddCompanionInput(const PersistedCompanionStatus &companionStatus,
    const DeviceStatus &deviceStatus, const std::vector<uint8_t> &addHostBindingReply)
{
    std::vector<uint16_t> protocolVersionList = { static_cast<uint16_t>(deviceStatus.protocolId) };
    std::vector<uint16_t> capabilityList = CapabilityConverter::ToUnderlyingVec(deviceStatus.capabilities);

    EndAddCompanionInput input = {};
    input.requestId = GetRequestId();
    input.companionStatus = companionStatus;
    input.secureProtocolId = secureProtocolId_;
    input.protocolVersionList = protocolVersionList;
    input.capabilityList = capabilityList;
    input.addHostBindingReply = addHostBindingReply;
    return input;
}

void HostAddCompanionRequest::ProcessEndAddCompanionOutput(const EndAddCompanionOutput &output,
    std::vector<uint8_t> &fwkMsg)
{
    needCancelCompanionAdd_ = false;
    templateId_ = output.templateId;
    desc_.SetTemplateId(templateId_);

    fwkMsg = output.fwkMsg;
    pendingTokenData_ = output.tokenData;
    tokenAuthAtl_ = output.atl;

    eventCollector_.SetTemplateIdList({ templateId_ });
    eventCollector_.SetAtl(output.atl);
    eventCollector_.SetEsl(output.esl);

    // Update enabled business IDs if parsed from additionalInfo
    if (!enabledBusinessIdsFromAdditionalInfo_.empty() && templateId_ != 0) {
        ResultCode ret =
            GetCompanionManager().UpdateCompanionEnabledBusinessIds(templateId_, enabledBusinessIdsFromAdditionalInfo_);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s UpdateCompanionEnabledBusinessIds failed ret=%{public}d", GetDescription(), ret);
        } else {
            IAM_LOGI("%{public}s updated enabled business IDs from additionalInfo", GetDescription());
        }
    }
}

bool HostAddCompanionRequest::EndAddCompanion(const BeginAddHostBindingReply &reply, std::vector<uint8_t> &fwkMsg)
{
    auto companionDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), companionDeviceKey.has_value(), false);

    auto deviceStatus = GetCrossDeviceCommManager().GetDeviceStatus(*companionDeviceKey);
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), deviceStatus.has_value(), false);

    auto companionStatusOpt = BuildPersistedCompanionStatus(*deviceStatus);
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), companionStatusOpt.has_value(), false);

    EndAddCompanionInput input = BuildEndAddCompanionInput(*companionStatusOpt, *deviceStatus, reply.extraInfo);
    EndAddCompanionOutput output = {};
    ResultCode ret = GetCompanionManager().EndAddCompanion(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s EndAddCompanion failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    enrollmentSucceeded_ = true;

    ProcessEndAddCompanionOutput(output, fwkMsg);
    return true;
}

bool HostAddCompanionRequest::SendEndAddHostBindingMsg(ResultCode result)
{
    auto companionDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), companionDeviceKey.has_value(), false);

    EndAddHostBindingRequest requestMsg = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionDeviceKey->deviceUserId,
        .result = result,
        .extraInfo = std::move(pendingTokenData_) }; // Contains encrypted token data (non-empty only when successful)
    pendingTokenData_.clear();
    Attributes request = {};
    EncodeEndAddHostBindingRequest(requestMsg, request);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::END_ADD_HOST_BINDING,
        request, [weakSelf = weak_from_this()](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleEndAddHostBindingReply(message);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return false;
    }
    return true;
}

void HostAddCompanionRequest::HandleEndAddHostBindingReply(const Attributes &reply)
{
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto replyMsgOpt = DecodeEndAddHostBindingReply(reply);
    ENSURE_OR_RETURN_DESC(GetDescription(), replyMsgOpt.has_value());

    const auto &replyMsg = *replyMsgOpt;

    if (replyMsg.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s token distribution failed result=%{public}d, but enrollment succeeded", GetDescription(),
            static_cast<int32_t>(replyMsg.result));
        errorGuard.Cancel();
        CompleteWithSuccess();
        return;
    }

    ENSURE_OR_RETURN_DESC(GetDescription(), templateId_ != 0);
    GetCompanionManager().SetCompanionTokenAuthAtl(templateId_, tokenAuthAtl_);
    IAM_LOGI("%{public}s token activated successfully", GetDescription());

    errorGuard.Cancel();
    CompleteWithSuccess();
}

void HostAddCompanionRequest::InvokeCallback(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    if (requestCallback_ == nullptr) {
        IAM_LOGI("%{public}s callback already sent", GetDescription());
        return;
    }
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [cb = std::move(requestCallback_), result, extra = extraInfo]() mutable {
            if (cb) {
                cb(result, extra);
            }
        });
    requestCallback_ = nullptr;
}

void HostAddCompanionRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s complete with error: %{public}d", GetDescription(), result);

    // After enrollment succeeded, token distribution failure is non-critical per spec
    if (enrollmentSucceeded_) {
        IAM_LOGI("%{public}s enrollment succeeded, complete with success", GetDescription());
        CompleteWithSuccess();
        return;
    }

    if (needCancelCompanionAdd_) {
        HostCancelAddCompanionInput input { GetRequestId() };
        ResultCode ret = GetSecurityAgent().HostCancelAddCompanion(input);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s HostCancelAddCompanion failed ret=%{public}d", GetDescription(), ret);
        }
        needCancelCompanionAdd_ = false;
    }
    InvokeCallback(result, {});
    eventCollector_.Report(result);
    Destroy();
}

void HostAddCompanionRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    InvokeCallback(ResultCode::SUCCESS, addCompanionFwkMsg_);
    needCancelCompanionAdd_ = false;
    eventCollector_.Report(ResultCode::SUCCESS);
    Destroy();
}

uint32_t HostAddCompanionRequest::GetMaxConcurrency() const
{
    return 1; // Spec: max 1 concurrent HostAddCompanionRequest
}

bool HostAddCompanionRequest::ShouldCancelOnNewRequest([[maybe_unused]] RequestType newRequestType,
    [[maybe_unused]] const std::optional<DeviceKey> &newPeerDevice,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostAddCompanionRequest preempts existing one
    if (newRequestType == RequestType::HOST_ADD_COMPANION_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostAddCompanion", GetDescription());
        return true;
    }

    // Spec: new HostDelegateAuthRequest preempts HostAddCompanionRequest
    if (newRequestType == RequestType::HOST_DELEGATE_AUTH_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostDelegateAuth", GetDescription());
        return true;
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
