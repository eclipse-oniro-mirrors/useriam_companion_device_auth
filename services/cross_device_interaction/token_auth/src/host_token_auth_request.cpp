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

#include "host_token_auth_request.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "companion_manager.h"
#include "companion_token_auth_handler.h"
#include "error_guard.h"
#include "iam_log_tracer.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "token_auth_message.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_TOKEN_AUTH_REQUEST

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostTokenAuthRequest::HostTokenAuthRequest(const AuthRequestParams &params, const DeviceKey &companionDeviceKey,
    FwkResultCallback &&requestCallback)
    : OutboundRequest(RequestType::HOST_TOKEN_AUTH_REQUEST, params.scheduleId, DEFAULT_REQUEST_TIMEOUT_MS),
      fwkMsg_(params.fwkMsg),
      hostUserId_(params.hostUserId),
      requestCallback_(std::move(requestCallback))
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

HostTokenAuthRequest::~HostTokenAuthRequest()
{
}

bool HostTokenAuthRequest::OnStart(ErrorGuard &errorGuard)
{
    IAM_LOGI("%{public}s start", GetDescription());
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), templateId_.has_value(), false);
    auto companionStatus = GetCompanionManager().GetCompanionStatus(*templateId_);
    if (!companionStatus.has_value()) {
        return false;
    }

    if (!companionStatus->tokenAuthAtl.has_value()) {
        IAM_LOGE("%{public}s token auth atl is null, companion not authorized for token auth", GetDescription());
        return false;
    }

    if (!GetCompanionManager().IsCapabilitySupported(*templateId_, Capability::TOKEN_AUTH)) {
        IAM_LOGE("%{public}s TOKEN_AUTH capability not supported by companion device", GetDescription());
        return false;
    }

    const DeviceKey &companionDeviceKey = companionStatus->companionDeviceStatus.deviceKey;
    if (!EnsureCompanionAuthMaintainActive(companionDeviceKey, errorGuard)) {
        return false;
    }

    companionUserId_ = companionStatus->companionDeviceStatus.deviceKey.deviceUserId;
    auto secureProtocolOpt = GetCrossDeviceCommManager().HostGetSecureProtocolId(companionDeviceKey);
    if (!secureProtocolOpt.has_value()) {
        return false;
    }
    secureProtocolId_ = secureProtocolOpt.value();
    if (!OpenConnection()) {
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return false;
    }
    eventCollector_.SetConnectionName(GetConnectionName());
    return true;
}

void HostTokenAuthRequest::OnConnected()
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    HostBeginTokenAuth();
}

std::weak_ptr<OutboundRequest> HostTokenAuthRequest::GetWeakPtr()
{
    return weak_from_this();
}

void HostTokenAuthRequest::HostBeginTokenAuth()
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    ENSURE_OR_RETURN_DESC(GetDescription(), templateId_.has_value());
    HostBeginTokenAuthInput input = {};
    input.requestId = GetRequestId();
    input.scheduleId = GetScheduleId();
    input.templateId = *templateId_;
    input.secureProtocolId = secureProtocolId_;
    input.fwkMsg = fwkMsg_;
    HostBeginTokenAuthOutput output = {};
    ResultCode ret = GetSecurityAgent().HostBeginTokenAuth(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostBeginTokenAuth failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }
    needEndTokenAuth_ = true;

    bool sendRet = SendTokenAuthRequest(output.tokenAuthRequest);
    if (!sendRet) {
        IAM_LOGE("%{public}s SendTokenAuthRequest failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

bool HostTokenAuthRequest::SendTokenAuthRequest(const std::vector<uint8_t> &tokenAuthRequest)
{
    DeviceKey hostDeviceKey = {};
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), localDeviceKey.has_value(), false);
    hostDeviceKey = localDeviceKey.value();
    hostDeviceKey.deviceUserId = hostUserId_;
    TokenAuthRequest requestMsg = { .hostDeviceKey = hostDeviceKey,
        .companionUserId = companionUserId_,
        .extraInfo = tokenAuthRequest };
    Attributes request = {};
    EncodeTokenAuthRequest(requestMsg, request);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::TOKEN_AUTH, request,
        [weakSelf = weak_from_this()](const Attributes &reply) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleTokenAuthReply(reply);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return false;
    }
    return true;
}

void HostTokenAuthRequest::HandleTokenAuthReply(const Attributes &reply)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    ENSURE_OR_RETURN_DESC(GetDescription(), templateId_.has_value());
    auto replyOpt = DecodeTokenAuthReply(reply);
    if (!replyOpt.has_value()) {
        IAM_LOGE("%{public}s decode reply failed", GetDescription());
        return;
    }
    const auto &replyMsg = *replyOpt;
    if (replyMsg.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s companion token auth failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(replyMsg.result));
        if (replyMsg.result == ResultCode::TOKEN_NOT_FOUND) {
            IAM_LOGI("%{public}s token not found, revoke token", GetDescription());
            (void)GetCompanionManager().SetCompanionTokenAuthAtl(*templateId_, std::nullopt);
        }
        errorGuard.UpdateErrorCode(replyMsg.result);
        return;
    }

    std::vector<uint8_t> tokenAuthReply = replyMsg.extraInfo;
    std::vector<uint8_t> fwkMsg = {};
    ResultCode endTokenAuthRet = SecureAgentEndTokenAuth(tokenAuthReply, fwkMsg);
    if (endTokenAuthRet != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s SecureAgentEndTokenAuth failed ret=%{public}d", GetDescription(),
            static_cast<int32_t>(endTokenAuthRet));
        if (endTokenAuthRet == ResultCode::TOKEN_VERIFY_FAILED) {
            IAM_LOGI("%{public}s token verify failed, set companion atl null", GetDescription());
            (void)GetCompanionManager().SetCompanionTokenAuthAtl(*templateId_, std::nullopt);
        }
        errorGuard.UpdateErrorCode(endTokenAuthRet);
        return;
    }
    needEndTokenAuth_ = false;
    errorGuard.Cancel();
    CompleteWithSuccess(fwkMsg);
}

ResultCode HostTokenAuthRequest::SecureAgentEndTokenAuth(const std::vector<uint8_t> &tokenAuthReply,
    std::vector<uint8_t> &outFwkMsg)
{
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), templateId_.has_value(), ResultCode::GENERAL_ERROR);
    HostEndTokenAuthInput input = {};
    input.requestId = GetRequestId();
    input.templateId = *templateId_;
    input.secureProtocolId = secureProtocolId_;
    input.tokenAuthReply = tokenAuthReply;

    HostEndTokenAuthOutput output = {};
    ResultCode ret = GetSecurityAgent().HostEndTokenAuth(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostEndTokenAuth failed ret=%{public}d", GetDescription(), ret);
        return ret;
    }
    outFwkMsg.swap(output.fwkMsg);
    return ResultCode::SUCCESS;
}

void HostTokenAuthRequest::InvokeCallback(ResultCode result, const std::vector<uint8_t> &extraInfo)
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

void HostTokenAuthRequest::CompleteWithError(ResultCode result)
{
    if (!AcquireCompletion()) {
        return;
    }
    IAM_LOGI("%{public}s: token auth request failed, result=%{public}d", GetDescription(), result);
    if (needEndTokenAuth_) {
        std::vector<uint8_t> fwkMsg = {};
        (void)SecureAgentEndTokenAuth({}, fwkMsg);
        needEndTokenAuth_ = false;
    }
    InvokeCallback(result, {});
    eventCollector_.Report(result);
    Destroy();
}

void HostTokenAuthRequest::CompleteWithSuccess(const std::vector<uint8_t> &extraInfo)
{
    if (!AcquireCompletion()) {
        return;
    }
    IAM_LOGI("%{public}s complete with success", GetDescription());
    InvokeCallback(ResultCode::SUCCESS, extraInfo);
    eventCollector_.Report(ResultCode::SUCCESS);
    Destroy();
}

uint32_t HostTokenAuthRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent HostTokenAuthRequest
}

bool HostTokenAuthRequest::CanStart(const std::vector<std::shared_ptr<IRequest>> &prevRequests) const
{
    if (CountSameType(prevRequests) >= GetMaxConcurrency()) {
        return false;
    }
    // Spec: HostTokenAuthRequest cannot run while HostIssueTokenRequest is active on the same device
    auto currentPeerDevice = GetPeerDeviceKey();
    for (const auto &req : prevRequests) {
        if (req != nullptr && req->GetRequestType() == RequestType::HOST_ISSUE_TOKEN_REQUEST) {
            auto reqPeerDevice = req->GetPeerDeviceKey();
            if (currentPeerDevice.has_value() && reqPeerDevice.has_value() &&
                currentPeerDevice.value() == reqPeerDevice.value()) {
                IAM_LOGI("%{public}s: blocked by HostIssueToken on same device", GetDescription());
                return false;
            }
        }
    }
    return true;
}

bool HostTokenAuthRequest::ShouldCancelOnNewRequest(const IRequest &newRequest,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostTokenAuthRequest to same peer device preempts existing one
    // Only preempt when both peerDeviceKeys are valid and equal
    if (newRequest.GetRequestType() == RequestType::HOST_TOKEN_AUTH_REQUEST) {
        auto currentPeerDevice = GetPeerDeviceKey();
        auto newPeerDevice = newRequest.GetPeerDeviceKey();
        if (currentPeerDevice.has_value() && newPeerDevice.has_value() &&
            currentPeerDevice.value() == newPeerDevice.value()) {
            IAM_LOGI("%{public}s: preempted by new HostTokenAuth to same device", GetDescription());
            return true;
        }
    }

    return false;
}

bool HostTokenAuthRequest::EnsureCompanionAuthMaintainActive(const DeviceKey &deviceKey, ErrorGuard &errorGuard)
{
    auto deviceStatus = GetCrossDeviceCommManager().GetDeviceStatus(deviceKey);
    if (!deviceStatus.has_value()) {
        IAM_LOGE("%{public}s failed to get device status", GetDescription());
        return false;
    }
    if (!deviceStatus->isAuthMaintainActive) {
        IAM_LOGE("%{public}s device not in auth maintain active state", GetDescription());
        return false;
    }
    deviceStatusSubscription_ = GetCrossDeviceCommManager().SubscribeDeviceStatus(deviceKey, false,
        [weakSelf = weak_from_this()](const std::vector<DeviceStatus> &deviceStatusList) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandlePeerDeviceStatusChanged(deviceStatusList);
        });
    if (deviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe device status", GetDescription());
        return false;
    }
    return true;
}

void HostTokenAuthRequest::HandlePeerDeviceStatusChanged(const std::vector<DeviceStatus> &deviceStatusList)
{
    LogTraceGuard guard;
    auto peerDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN_DESC(GetDescription(), peerDeviceKey.has_value());
    for (const auto &status : deviceStatusList) {
        if (status.deviceKey != *peerDeviceKey) {
            continue;
        }
        if (!status.isAuthMaintainActive) {
            IAM_LOGE("%{public}s companion device left auth maintain state", GetDescription());
            CompleteWithError(ResultCode::GENERAL_ERROR);
        }
        return;
    }
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
