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

#include "companion_add_companion_request.h"

#include <utility>

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "add_companion_message.h"
#include "common_message.h"
#include "error_guard.h"
#include "security_agent.h"
#include "service_common.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_COMPANION_ADD_COMPANION_REQUEST

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionAddCompanionRequest::CompanionAddCompanionRequest(const std::string &connectionName, const Attributes &request,
    OnMessageReply &&replyCallback, const DeviceKey &hostDeviceKey)
    : InboundRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, connectionName, hostDeviceKey),
      initKeyNegoRequest_(request),
      currentReply_(std::move(replyCallback))
{
}

bool CompanionAddCompanionRequest::OnStart(ErrorGuard &errorGuard)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());

    auto companionKeyOpt = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), companionKeyOpt.has_value(), false);
    companionDeviceKey_ = *companionKeyOpt;

    eventCollector_.SetHostDeviceKey(PeerDeviceKey());
    eventCollector_.SetCompanionUserId(companionDeviceKey_.deviceUserId);
    eventCollector_.SetConnectionName(GetConnectionName());

    secureProtocolId_ = GetCrossDeviceCommManager().CompanionGetSecureProtocolId();
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), secureProtocolId_ != SecureProtocolId::INVALID, false);

    beginAddHostBindingSubscription_ =
        GetCrossDeviceCommManager().SubscribeMessage(GetConnectionName(), MessageType::BEGIN_ADD_HOST_BINDING,
            [weakSelf = weak_from_this()](const Attributes &msg, OnMessageReply &onMessageReply) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleBeginAddCompanion(msg, onMessageReply);
            });
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), beginAddHostBindingSubscription_ != nullptr, false);

    endAddHostBindingSubscription_ =
        GetCrossDeviceCommManager().SubscribeMessage(GetConnectionName(), MessageType::END_ADD_HOST_BINDING,
            [weakSelf = weak_from_this()](const Attributes &msg, OnMessageReply &onMessageReply) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleEndAddCompanion(msg, onMessageReply);
            });
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), endAddHostBindingSubscription_ != nullptr, false);

    auto initRequestOpt = DecodeInitKeyNegotiationRequest(initKeyNegoRequest_);
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), initRequestOpt.has_value(), false);
    if (initRequestOpt->hostDeviceKey != PeerDeviceKey()) {
        IAM_LOGE("%{public}s host device key mismatch", GetDescription());
        return false;
    }

    std::vector<uint8_t> initKeyNegotiationReply;
    bool initRet = CompanionInitKeyNegotiation(*initRequestOpt, initKeyNegotiationReply);
    if (!initRet) {
        IAM_LOGE("%{public}s CompanionInitKeyNegotiation failed", GetDescription());
        return false;
    }

    bool ret = SendInitKeyNegotiationReply(ResultCode::SUCCESS, initKeyNegotiationReply);
    if (!ret) {
        IAM_LOGE("%{public}s SendInitKeyNegotiationReply failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return false;
    }

    errorGuard.Cancel();
    return true;
}

CompanionInitKeyNegotiationInput CompanionAddCompanionRequest::BuildCompanionInitKeyNegotiationInput(
    const LocalDeviceProfile &profile, const std::vector<uint8_t> &initKeyNegotiationRequest)
{
    CompanionInitKeyNegotiationInput input = {};
    input.requestId = GetRequestId();
    input.secureProtocolId = secureProtocolId_;
    input.protocolList = ProtocolIdConverter::ToUnderlyingVec(profile.protocols);
    input.capabilityList = CapabilityConverter::ToUnderlyingVec(profile.companionCapabilities);
    input.companionDeviceKey = companionDeviceKey_;
    input.hostDeviceKey = PeerDeviceKey();
    input.initKeyNegotiationRequest = initKeyNegotiationRequest;
    return input;
}

BeginAddHostBindingInput CompanionAddCompanionRequest::BuildBeginAddHostBindingInput(int32_t companionUserId,
    const std::vector<uint8_t> &addHostBindingRequest) const
{
    BeginAddHostBindingInput input = {};
    input.requestId = GetRequestId();
    input.companionUserId = companionUserId;
    input.secureProtocolId = secureProtocolId_;
    input.addHostBindingRequest = addHostBindingRequest;
    return input;
}

void CompanionAddCompanionRequest::ProcessCompanionInitKeyNegotiationOutput(
    const CompanionInitKeyNegotiationOutput &output, std::vector<uint8_t> &initKeyNegotiationReply)
{
    needCancelAddCompanion_ = true;

    eventCollector_.SetAlgorithmList(output.algorithmList);
    eventCollector_.SetSelectedAlgorithm(output.selectedAlgorithm);

    initKeyNegotiationReply = output.initKeyNegotiationReply;
}

bool CompanionAddCompanionRequest::CompanionInitKeyNegotiation(const InitKeyNegotiationRequest &request,
    std::vector<uint8_t> &initKeyNegotiationReply)
{
    IAM_LOGI("%{public}s start", GetDescription());

    auto profile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    CompanionInitKeyNegotiationInput input = BuildCompanionInitKeyNegotiationInput(profile, request.extraInfo);

    CompanionInitKeyNegotiationOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionInitKeyNegotiation(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionInitKeyNegotiation failed ret=%{public}d", GetDescription(), ret);
        return false;
    }

    ProcessCompanionInitKeyNegotiationOutput(output, initKeyNegotiationReply);
    return true;
}

bool CompanionAddCompanionRequest::SendInitKeyNegotiationReply(ResultCode result,
    const std::vector<uint8_t> &initKeyNegotiationReply)
{
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), currentReply_ != nullptr, false);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = result, .extraInfo = initKeyNegotiationReply };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    currentReply_(reply);
    currentReply_ = nullptr;
    return true;
}

ResultCode CompanionAddCompanionRequest::CallBeginAddHostBinding(int32_t companionUserId,
    const std::vector<uint8_t> &extraInfo, BeginAddHostBindingOutput &beginOutput)
{
    BeginAddHostBindingInput beginInput = BuildBeginAddHostBindingInput(companionUserId, extraInfo);
    return GetHostBindingManager().BeginAddHostBinding(beginInput, beginOutput);
}

void CompanionAddCompanionRequest::HandleBeginAddCompanion(const Attributes &attrInput, OnMessageReply &onMessageReply)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    ENSURE_OR_RETURN_DESC(GetDescription(), onMessageReply != nullptr);

    currentReply_ = std::move(onMessageReply);
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto requestOpt = DecodeBeginAddHostBindingRequest(attrInput);
    ENSURE_OR_RETURN_DESC(GetDescription(), requestOpt.has_value());
    ENSURE_OR_RETURN_DESC(GetDescription(), requestOpt->companionUserId == companionDeviceKey_.deviceUserId);

    BeginAddHostBindingOutput beginOutput = {};
    ResultCode ret = CallBeginAddHostBinding(requestOpt->companionUserId, requestOpt->extraInfo, beginOutput);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CallBeginAddHostBinding failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }
    desc_.SetBindingId(beginOutput.bindingId);
    bindingId_ = beginOutput.bindingId;
    eventCollector_.SetBindingId(beginOutput.bindingId);

    BeginAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = beginOutput.addHostBindingReply };
    Attributes reply;
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    currentReply_(reply);
    currentReply_ = nullptr;

    errorGuard.Cancel();
}

void CompanionAddCompanionRequest::HandleEndAddCompanion(const Attributes &attrInput, OnMessageReply &onMessageReply)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    ENSURE_OR_RETURN_DESC(GetDescription(), onMessageReply != nullptr);

    currentReply_ = std::move(onMessageReply);
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto requestOpt = DecodeEndAddHostBindingRequest(attrInput);
    ENSURE_OR_RETURN_DESC(GetDescription(), requestOpt.has_value());
    ENSURE_OR_RETURN_DESC(GetDescription(), requestOpt->hostDeviceKey == PeerDeviceKey());

    IAM_LOGI("%{public}s Get resultCode %{public}d hostUserId %{public}d companionUserId %{public}d", GetDescription(),
        requestOpt->result, requestOpt->hostDeviceKey.deviceUserId, requestOpt->companionUserId);

    // Extract Token data if binding was successful
    std::vector<uint8_t> tokenData;
    if (requestOpt->result == ResultCode::SUCCESS && !requestOpt->extraInfo.empty()) {
        tokenData = requestOpt->extraInfo;
        IAM_LOGI("%{public}s receive token data from host, size=%{public}zu", GetDescription(), tokenData.size());
    }

    EndAddHostBindingOutput endOutput = {};
    ResultCode ret = EndAddHostBinding(requestOpt->result, std::move(tokenData), endOutput);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s EndAddHostBinding failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }
    needCancelAddCompanion_ = false;

    eventCollector_.SetAtl(endOutput.atl);
    eventCollector_.SetEsl(endOutput.esl);

    EndAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS };
    Attributes reply;
    EncodeEndAddHostBindingReply(replyMsg, reply);

    currentReply_(reply);
    currentReply_ = nullptr;

    errorGuard.Cancel();
    CompleteWithSuccess();
}

ResultCode CompanionAddCompanionRequest::EndAddHostBinding(ResultCode resultCode, std::vector<uint8_t> &&tokenData,
    EndAddHostBindingOutput &output)
{
    EndAddHostBindingInput input = {};
    input.requestId = GetRequestId();
    input.resultCode = resultCode;
    input.bindingId = bindingId_.value_or(0);
    input.tokenData = std::move(tokenData);
    return GetHostBindingManager().EndAddHostBinding(input, output);
}

std::weak_ptr<InboundRequest> CompanionAddCompanionRequest::GetWeakPtr()
{
    return weak_from_this();
}

void CompanionAddCompanionRequest::SendErrorReply(ResultCode result)
{
    if (currentReply_ == nullptr) {
        IAM_LOGE("%{public}s reply already sent", GetDescription());
        return;
    }

    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);

    currentReply_(reply);
    currentReply_ = nullptr;
}

void CompanionAddCompanionRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGE("%{public}s complete with error: %{public}d", GetDescription(), result);
    SendErrorReply(result);
    if (needCancelAddCompanion_) {
        EndAddHostBindingOutput endOutput = {};
        ResultCode ret = EndAddHostBinding(result, {}, endOutput);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s EndAddHostBinding cancel failed ret=%{public}d", GetDescription(), ret);
        }
        needCancelAddCompanion_ = false;

        eventCollector_.SetAtl(endOutput.atl);
        eventCollector_.SetEsl(endOutput.esl);
    }
    eventCollector_.Report(result);
    Destroy();
}

void CompanionAddCompanionRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    eventCollector_.Report(ResultCode::SUCCESS);
    Destroy();
}

uint32_t CompanionAddCompanionRequest::GetMaxConcurrency() const
{
    return 1; // Spec: max 1 concurrent CompanionAddCompanionRequest
}

bool CompanionAddCompanionRequest::ShouldCancelOnNewRequest(const IRequest &newRequest,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new CompanionAddCompanionRequest preempts existing one
    if (newRequest.GetRequestType() == RequestType::COMPANION_ADD_COMPANION_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new CompanionAddCompanion", GetDescription());
        return true;
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
