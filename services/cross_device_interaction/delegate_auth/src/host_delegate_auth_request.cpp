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

#include <cinttypes>

#include <nlohmann/json.hpp>

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
      requestCallback_(std::move(requestCallback)),
      selectContext_(params.selectContext),
      widgetAuthParam_(params.widgetAuthParam)
{
    templateId_ = params.templateId;
    SetPeerDeviceKey(companionDeviceKey);
    desc_.SetTemplateId(params.templateId);
    desc_.SetDeviceId(companionDeviceKey);
    eventCollector_.SetHostUserId(params.hostUserId);
    eventCollector_.SetCompanionDeviceKey(companionDeviceKey);
    eventCollector_.SetScheduleId(params.scheduleId);
    eventCollector_.SetTriggerReason("authIntent " + std::to_string(params.authIntent));
    eventCollector_.SetTemplateIdList({ params.templateId });
}

bool HostDelegateAuthRequest::OnStart(ErrorGuard &errorGuard)
{
    IAM_LOGI("%{public}s start", GetDescription());
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), templateId_.has_value(), false);
    if (!GetCompanionManager().IsCapabilitySupported(*templateId_, Capability::DELEGATE_AUTH)) {
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
                self->HandleSendDelegateAuthResultMessage(request, onMessageReply);
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

    ENSURE_OR_RETURN_DESC(GetDescription(), templateId_.has_value());
    HostBeginDelegateAuthInput input = { GetRequestId(), GetScheduleId(), *templateId_, fwkMsg_ };
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
    std::vector<int32_t> authTypes;
    for (auto type : widgetAuthParam_.authTypes) {
        authTypes.push_back(static_cast<int32_t>(type));
    }
    StartDelegateAuthRequest startRequest = { .hostDeviceKey = hostDeviceKey,
        .companionUserId = peerDeviceKey->deviceUserId,
        .extraInfo = output.startDelegateAuthRequest,
        .selectContext = selectContext_,
        .remoteTokenId = GetRemoteTokenId(*peerDeviceKey),
        .authTypes = authTypes,
        .navigationButtonText = widgetAuthParam_.navigationButtonText };
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

ResultCode HostDelegateAuthRequest::HandleSendDelegateAuthResult(const Attributes &request,
    std::vector<uint8_t> &outFwkMsg)
{
    IAM_LOGI("%{public}s start", GetDescription());

    auto resultMsgOpt = DecodeSendDelegateAuthResultRequest(request);
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), resultMsgOpt.has_value(), ResultCode::GENERAL_ERROR);
    const auto &resultMsg = *resultMsgOpt;
    HostEndDelegateAuthOutput output = {};
    if (!CallSecurityAgentEndDelegateAuth(resultMsg.extraInfo, output)) {
        return ResultCode::GENERAL_ERROR;
    }
    if (resultMsg.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s delegate auth failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(resultMsg.result));
        return resultMsg.result;
    }
    IAM_LOGI("%{public}s delegate auth success authType=%{public}d atl=%{public}d", GetDescription(), output.authType,
        output.atl);
    eventCollector_.SetSuccessAuthType(static_cast<int32_t>(output.authType));
    eventCollector_.SetAtl(output.atl);
    outFwkMsg = output.fwkMsg;
    needCancelDelegateAuth_ = false;
    return ResultCode::SUCCESS;
}

void HostDelegateAuthRequest::HandleSendDelegateAuthResultMessage(const Attributes &request,
    OnMessageReply &onMessageReply)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s HandleSendDelegateAuthResultMessage", GetDescription());
    ENSURE_OR_RETURN_DESC(GetDescription(), onMessageReply != nullptr);
    ErrorGuard errorGuard([this, &onMessageReply](ResultCode code) {
        Attributes reply;
        reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(code));
        onMessageReply(reply);
        CompleteWithError(code);
    });

    std::vector<uint8_t> fwkMsg;
    ResultCode result = HandleSendDelegateAuthResult(request, fwkMsg);
    if (result != ResultCode::SUCCESS) {
        errorGuard.UpdateErrorCode(result);
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

std::optional<uint32_t> HostDelegateAuthRequest::GetRemoteTokenId(const DeviceKey &deviceKey)
{
    if (!selectContext_.has_value() || selectContext_->empty()) {
        IAM_LOGE("%{public}s selectContext_ is empty", GetDescription());
        return std::nullopt;
    }

    std::string jsonStr(selectContext_->begin(), selectContext_->end());
    try {
        auto json = nlohmann::json::parse(jsonStr);
        auto it = json.find("deviceSelectContext");
        if (it == json.end()) {
            IAM_LOGE("%{public}s deviceSelectContext not found in json", GetDescription());
            return std::nullopt;
        }
        if (!it->is_array()) {
            IAM_LOGE("%{public}s deviceSelectContext is not array", GetDescription());
            return std::nullopt;
        }
        for (const auto &deviceEntry : *it) {
            if (!deviceEntry.contains("deviceIdType") || !deviceEntry.contains("deviceId") ||
                !deviceEntry.contains("deviceUserId") || !deviceEntry.contains("remoteTokenId")) {
                continue;
            }
            if (!deviceEntry.at("deviceIdType").is_number_integer() || !deviceEntry.at("deviceId").is_string() ||
                !deviceEntry.at("deviceUserId").is_number_integer() ||
                !deviceEntry.at("remoteTokenId").is_number_unsigned()) {
                IAM_LOGE("%{public}s invalid json data type in deviceSelectContext", GetDescription());
                continue;
            }
            auto idType = deviceEntry.at("deviceIdType").get<int32_t>();
            auto deviceId = deviceEntry.at("deviceId").get<std::string>();
            auto deviceUserId = deviceEntry.at("deviceUserId").get<int32_t>();
            if (idType == static_cast<int32_t>(deviceKey.idType) && deviceId == deviceKey.deviceId &&
                deviceUserId == deviceKey.deviceUserId) {
                IAM_LOGI("GetRemoteTokenId success");
                return deviceEntry.at("remoteTokenId").get<uint32_t>();
            }
        }
        IAM_LOGE("%{public}s device not found in selectContext", GetDescription());
        return std::nullopt;
    } catch (const nlohmann::json::exception &e) {
        IAM_LOGE("%{public}s json parse error: %{public}s", GetDescription(), e.what());
        return std::nullopt;
    }
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

bool HostDelegateAuthRequest::ShouldCancelOnNewRequest(const IRequest &newRequest,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostAddCompanionRequest preempts HostDelegateAuthRequest
    if (newRequest.GetRequestType() == RequestType::HOST_ADD_COMPANION_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostAddCompanion", GetDescription());
        return true;
    }

    // Spec: new HostDelegateAuthRequest to same device preempts existing one
    if (newRequest.GetRequestType() == RequestType::HOST_DELEGATE_AUTH_REQUEST) {
        auto currentPeerDevice = GetPeerDeviceKey();
        auto newPeerDevice = newRequest.GetPeerDeviceKey();
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
