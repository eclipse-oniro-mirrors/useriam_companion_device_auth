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

#include "host_delegate_auth_request.h"

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "common_defines.h"
#include "companion_manager.h"
#include "delegate_auth_message.h"
#include "error_guard.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_DELEGATE_AUTH_REQUEST

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostDelegateAuthRequest::HostDelegateAuthRequest(const AuthRequestParams &params, const DeviceKey &companionDeviceKey,
    FwkResultCallback &&requestCallback)
    : OutboundRequest(RequestType::HOST_DELEGATE_AUTH_REQUEST, params.scheduleId, DEFAULT_REQUEST_TIMEOUT_MS),
      fwkMsg_(params.fwkMsg),
      hostUserId_(params.hostUserId),
      templateId_(params.templateId),
      requestCallback_(std::move(requestCallback))
{
    SetPeerDeviceKey(companionDeviceKey);
    desc_.SetTemplateId(templateId_);
    eventCollector_.SetHostUserId(params.hostUserId);
    eventCollector_.SetCompanionDeviceKey(companionDeviceKey);
    eventCollector_.SetScheduleId(params.scheduleId);
    eventCollector_.SetTriggerReason("authIntent " + std::to_string(params.authIntent));
    eventCollector_.SetTemplateIdList({ params.templateId });
}

bool HostDelegateAuthRequest::OnStart(ErrorGuard &errorGuard)
{
    IAM_LOGI("%{public}s start", GetDescription());
    if (!GetCompanionManager().IsCapabilitySupported(templateId_, Capability::DELEGATE_AUTH)) {
        IAM_LOGE("%{public}s DELEGATE_AUTH capability not supported by companion device", GetDescription());
        return false;
    }

    auto peerDeviceKey = GetPeerDeviceKey();
    if (!peerDeviceKey.has_value()) {
        IAM_LOGE("%{public}s peerDeviceKey not set", GetDescription());
        return false;
    }
    auto secureProtocolOpt = GetCrossDeviceCommManager().HostGetSecureProtocolId(*peerDeviceKey);
    if (!secureProtocolOpt.has_value()) {
        IAM_LOGE("%{public}s HostGetSecureProtocolId fail", GetDescription());
        return false;
    }
    secureProtocolId_ = secureProtocolOpt.value();
    if (!OpenConnection()) {
        IAM_LOGE("%{public}s OpenConnection fail", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return false;
    }
    eventCollector_.SetConnectionName(GetConnectionName());
    errorGuard.Cancel();
    return true;
}

void HostDelegateAuthRequest::OnConnected()
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    HostBeginDelegateAuth();
}

bool HostDelegateAuthRequest::InitDelegateResultSubscription()
{
    if (delegateResultSubscription_) {
        return true;
    }
    delegateResultSubscription_ =
        GetCrossDeviceCommManager().SubscribeMessage(GetConnectionName(), MessageType::SEND_DELEGATE_AUTH_RESULT,
            [weakSelf = weak_from_this()](const Attributes &request, OnMessageReply &onMessageReply) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleSendDelegateAuthRequestMsg(request, onMessageReply);
            });
    if (delegateResultSubscription_ == nullptr) {
        IAM_LOGE("%{public}s subscribe delegate result failed", GetDescription());
        return false;
    }
    return true;
}

void HostDelegateAuthRequest::HostBeginDelegateAuth()
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    if (!InitDelegateResultSubscription()) {
        IAM_LOGE("%{public}s InitDelegateResultSubscription failed", GetDescription());
        return;
    }

    HostBeginDelegateAuthInput input = {};
    input.requestId = GetRequestId();
    input.scheduleId = GetScheduleId();
    input.templateId = templateId_;
    input.fwkMsg = fwkMsg_;
    HostBeginDelegateAuthOutput output = {};
    ResultCode ret = GetSecurityAgent().HostBeginDelegateAuth(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostBeginDelegateAuth failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    needCancelDelegateAuth_ = true;
    auto peerDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN_DESC(GetDescription(), peerDeviceKey.has_value());
    DeviceKey hostDeviceKey = {};
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_DESC(GetDescription(), localDeviceKey.has_value());
    hostDeviceKey = localDeviceKey.value();
    hostDeviceKey.deviceUserId = hostUserId_;
    StartDelegateAuthRequest startRequest = { .hostDeviceKey = hostDeviceKey,
        .companionUserId = peerDeviceKey->deviceUserId,
        .extraInfo = output.startDelegateAuthRequest };
    Attributes request = {};
    EncodeStartDelegateAuthRequest(startRequest, request);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::START_DELEGATE_AUTH,
        request, [weakSelf = weak_from_this()](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleStartDelegateAuthReply(message);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return;
    }
    errorGuard.Cancel();
}

void HostDelegateAuthRequest::HandleStartDelegateAuthReply(const Attributes &message)
{
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyOpt = DecodeStartDelegateAuthReply(message);
    ENSURE_OR_RETURN_DESC(GetDescription(), replyOpt.has_value());
    if (replyOpt->result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s start delegate auth failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(replyOpt->result));
        errorGuard.UpdateErrorCode(replyOpt->result);
        return;
    }

    IAM_LOGI("%{public}s start delegate auth success", GetDescription());
    errorGuard.Cancel();
}

bool HostDelegateAuthRequest::CallSecurityAgentEndDelegateAuth(const std::vector<uint8_t> &delegateAuthResult,
    HostEndDelegateAuthOutput &output)
{
    HostEndDelegateAuthInput input = {};
    input.requestId = GetRequestId();
    input.secureProtocolId = secureProtocolId_;
    input.delegateAuthResult = delegateAuthResult;
    ResultCode ret = GetSecurityAgent().HostEndDelegateAuth(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostEndDelegateAuth failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    return true;
}

bool HostDelegateAuthRequest::HandleSendDelegateAuthRequest(const Attributes &request, std::vector<uint8_t> &outFwkMsg)
{
    IAM_LOGI("%{public}s start", GetDescription());

    auto resultMsgOpt = DecodeSendDelegateAuthResultRequest(request);
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), resultMsgOpt.has_value(), false);
    const auto &resultMsg = *resultMsgOpt;
    HostEndDelegateAuthOutput output = {};
    if (!CallSecurityAgentEndDelegateAuth(resultMsg.extraInfo, output)) {
        return false;
    }
    if (resultMsg.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s delegate auth failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(resultMsg.result));
        return false;
    }
    IAM_LOGI("%{public}s delegate auth success authType=%{public}d atl=%{public}d", GetDescription(), output.authType,
        output.atl);
    eventCollector_.SetSuccessAuthType(static_cast<int32_t>(output.authType));
    eventCollector_.SetAtl(output.atl);
    outFwkMsg = output.fwkMsg;
    needCancelDelegateAuth_ = false;
    return true;
}

void HostDelegateAuthRequest::HandleSendDelegateAuthRequestMsg(const Attributes &request,
    OnMessageReply &onMessageReply)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s HandleSendDelegateAuthRequestMsg", GetDescription());
    ENSURE_OR_RETURN_DESC(GetDescription(), onMessageReply != nullptr);
    ErrorGuard errorGuard([this, &onMessageReply](ResultCode code) {
        Attributes reply;
        reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(code));
        onMessageReply(reply);
        CompleteWithError(code);
    });

    std::vector<uint8_t> fwkMsg;
    bool result = HandleSendDelegateAuthRequest(request, fwkMsg);
    if (!result) {
        return;
    }

    Attributes reply = {};
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));
    onMessageReply(reply);

    errorGuard.Cancel();
    CompleteWithSuccess(fwkMsg);
}

std::weak_ptr<OutboundRequest> HostDelegateAuthRequest::GetWeakPtr()
{
    return weak_from_this();
}

void HostDelegateAuthRequest::InvokeCallback(ResultCode result, const std::vector<uint8_t> &fwkMsg)
{
    if (requestCallback_ == nullptr) {
        IAM_LOGI("%{public}s callback already sent", GetDescription());
        return;
    }
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [cb = std::move(requestCallback_), result, msg = fwkMsg]() mutable {
            if (cb) {
                cb(result, msg);
            }
        });
    requestCallback_ = nullptr;
}

void HostDelegateAuthRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s: delegate auth request failed, result=%{public}d", GetDescription(), result);
    InvokeCallback(result, {});
    if (needCancelDelegateAuth_) {
        HostCancelDelegateAuthInput input = { GetRequestId() };
        ResultCode ret = GetSecurityAgent().HostCancelDelegateAuth(input);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s HostCancelDelegateAuth failed ret=%{public}d", GetDescription(), ret);
        }
        needCancelDelegateAuth_ = false;
    }
    eventCollector_.Report(result);
    Destroy();
}

void HostDelegateAuthRequest::CompleteWithSuccess(const std::vector<uint8_t> &fwkMsg)
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    needCancelDelegateAuth_ = false;
    InvokeCallback(ResultCode::SUCCESS, fwkMsg);
    eventCollector_.Report(ResultCode::SUCCESS);
    Destroy();
}

uint32_t HostDelegateAuthRequest::GetMaxConcurrency() const
{
    return 1; // Spec: max 1 concurrent HostDelegateAuthRequest, must specify device
}

bool HostDelegateAuthRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    const std::optional<DeviceKey> &newPeerDevice, [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostAddCompanionRequest preempts HostDelegateAuthRequest
    if (newRequestType == RequestType::HOST_ADD_COMPANION_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostAddCompanion", GetDescription());
        return true;
    }

    // Spec: new HostDelegateAuthRequest to same device preempts existing one
    if (newRequestType == RequestType::HOST_DELEGATE_AUTH_REQUEST) {
        auto currentPeerDevice = GetPeerDeviceKey();
        if (currentPeerDevice.has_value() && newPeerDevice.has_value() &&
            currentPeerDevice.value() == newPeerDevice.value()) {
            IAM_LOGI("%{public}s: preempted by new HostDelegateAuth to same device", GetDescription());
            return true;
        }
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
