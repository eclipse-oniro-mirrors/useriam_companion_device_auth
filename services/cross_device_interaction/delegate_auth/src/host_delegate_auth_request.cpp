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
#include "iam_logger.h"

#include "common_defines.h"
#include "companion_manager.h"
#include "cross_device_comm_manager_impl.h"
#include "delegate_auth_message.h"
#include "error_guard.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostDelegateAuthRequest::HostDelegateAuthRequest(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg,
    UserId hostUserId, TemplateId templateId, FwkResultCallback &&requestCallback)
    : OutboundRequest(RequestType::HOST_DELEGATE_AUTH_REQUEST, scheduleId, DEFAULT_REQUEST_TIMEOUT_MS),
      fwkMsg_(fwkMsg),
      hostUserId_(hostUserId),
      templateId_(templateId),
      requestCallback_(std::move(requestCallback))
{
}

bool HostDelegateAuthRequest::OnStart(ErrorGuard &errorGuard)
{
    IAM_LOGI("%{public}s start", GetDescription());
    auto companionStatus = GetCompanionManager().GetCompanionStatus(templateId_);
    if (!companionStatus.has_value()) {
        IAM_LOGI("%{public}s GetCompanionStatus fail", GetDescription());
        return false;
    }
    const DeviceKey &companionDeviceKey = companionStatus->companionDeviceStatus.deviceKey;
    SetPeerDeviceKey(companionDeviceKey);
    auto secureProtocolOpt = GetCrossDeviceCommManager().HostGetSecureProtocolId(companionDeviceKey);
    if (!secureProtocolOpt.has_value()) {
        IAM_LOGI("%{public}s HostGetSecureProtocolId fail", GetDescription());
        return false;
    }
    secureProtocolId_ = secureProtocolOpt.value();
    if (!OpenConnection()) {
        IAM_LOGI("%{public}s OpenConnection fail", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return false;
    }
    errorGuard.Cancel();
    return true;
}

void HostDelegateAuthRequest::OnConnected()
{
    IAM_LOGI("%{public}s", GetDescription());
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
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
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
    ENSURE_OR_RETURN(peerDeviceKey.has_value());
    DeviceKey hostDeviceKey = {};
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    if (localDeviceKey.has_value()) {
        hostDeviceKey = *localDeviceKey;
    }
    hostDeviceKey.deviceUserId = hostUserId_;
    StartDelegateAuthRequest startRequest = { .hostDeviceKey = hostDeviceKey,
        .companionUserId = peerDeviceKey->deviceUserId,
        .extraInfo = output.startDelegateAuthRequest };
    Attributes request = {};
    bool encodeRet = EncodeStartDelegateAuthRequest(startRequest, request);
    ENSURE_OR_RETURN(encodeRet);

    auto weakSelf = std::weak_ptr<HostDelegateAuthRequest>(shared_from_this());
    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::START_DELEGATE_AUTH,
        request, [weakSelf](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleStartDelegateAuthReply(message);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return;
    }
    errorGuard.Cancel();
}

void HostDelegateAuthRequest::HandleStartDelegateAuthReply(const Attributes &message)
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyOpt = DecodeStartDelegateAuthReply(message);
    ENSURE_OR_RETURN(replyOpt.has_value());
    if (replyOpt->result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s start delegate auth failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(replyOpt->result));
        errorGuard.UpdateErrorCode(replyOpt->result);
        return;
    }

    IAM_LOGI("%{public}s start delegate auth success", GetDescription());
    errorGuard.Cancel();
}

bool HostDelegateAuthRequest::HandleSendDelegateAuthRequest(const Attributes &request, std::vector<uint8_t> &fwkMsg)
{
    IAM_LOGI("%{public}s", GetDescription());

    auto resultMsgOpt = DecodeSendDelegateAuthResultRequest(request);
    ENSURE_OR_RETURN_VAL(resultMsgOpt.has_value(), false);
    const auto &resultMsg = *resultMsgOpt;
    HostEndDelegateAuthInput input = {};
    input.requestId = GetRequestId();
    input.secureProtocolId = secureProtocolId_;
    input.delegateAuthResult = resultMsg.extraInfo;
    HostEndDelegateAuthOutput output = {};
    ResultCode ret = GetSecurityAgent().HostEndDelegateAuth(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostEndDelegateAuth failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    if (resultMsg.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s delegate auth failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(resultMsg.result));
        return false;
    }
    IAM_LOGI("%{public}s delegate auth success authType=%{public}d atl=%{public}d", GetDescription(), output.authType,
        output.atl);
    fwkMsg = output.fwkMsg;
    needCancelDelegateAuth_ = false;
    return true;
}

void HostDelegateAuthRequest::HandleSendDelegateAuthRequestMsg(const Attributes &request,
    OnMessageReply &onMessageReply)
{
    IAM_LOGI("%{public}s HandleSendDelegateAuthRequestMsg", GetDescription());
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
    return shared_from_this();
}

void HostDelegateAuthRequest::InvokeCallback(ResultCode result, const std::vector<uint8_t> &fwkMsg)
{
    if (callbackInvoked_) {
        IAM_LOGI("%{public}s callback already sent", GetDescription());
        return;
    }
    ENSURE_OR_RETURN(requestCallback_ != nullptr);
    callbackInvoked_ = true;
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [cb = std::move(requestCallback_), result, msg = fwkMsg]() mutable {
            if (cb) {
                cb(result, msg);
            }
        });
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
    Destroy();
}

void HostDelegateAuthRequest::CompleteWithSuccess(const std::vector<uint8_t> &fwkMsg)
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    needCancelDelegateAuth_ = false;
    InvokeCallback(ResultCode::SUCCESS, fwkMsg);
    Destroy();
}

uint32_t HostDelegateAuthRequest::GetMaxConcurrency() const
{
    return 1; // Spec: max 1 concurrent HostDelegateAuthRequest, must specify device
}

bool HostDelegateAuthRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    [[maybe_unused]] const std::optional<DeviceKey> &newPeerDevice,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostAddCompanionRequest preempts HostDelegateAuthRequest
    if (newRequestType == RequestType::HOST_ADD_COMPANION_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostAddCompanion", GetDescription());
        return true;
    }

    // Spec: new HostDelegateAuthRequest preempts existing one
    if (newRequestType == RequestType::HOST_DELEGATE_AUTH_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostDelegateAuth", GetDescription());
        return true;
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
