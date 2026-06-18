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

#include "host_issue_token_request.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "companion_manager.h"
#include "companion_pre_issue_token_handler.h"
#include "error_guard.h"
#include "iam_log_tracer.h"
#include "issue_token_message.h"
#include "security_agent.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_ISSUE_TOKEN_REQUEST

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostIssueTokenRequest::HostIssueTokenRequest(UserId hostUserId, TemplateId templateId, uint32_t lockStateAuthTypeValue,
    const std::vector<uint8_t> &fwkUnlockMsg, const DeviceKey &companionDeviceKey)
    : OutboundRequest(RequestType::HOST_ISSUE_TOKEN_REQUEST, 0, DEFAULT_REQUEST_TIMEOUT_MS),
      hostUserId_(hostUserId),
      fwkUnlockMsg_(fwkUnlockMsg)
{
    templateId_ = templateId;
    SetPeerDeviceKey(companionDeviceKey);
    desc_.SetTemplateId(templateId);
    desc_.SetDeviceId(companionDeviceKey);
    eventCollector_.SetHostUserId(hostUserId);
    eventCollector_.SetCompanionDeviceKey(companionDeviceKey);
    eventCollector_.SetTriggerReason("host device auth type " + std::to_string(lockStateAuthTypeValue) + " success");
    eventCollector_.SetTemplateIdList({ templateId });
}

bool HostIssueTokenRequest::OnStart(ErrorGuard &errorGuard)
{
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), templateId_.has_value(), false);
    auto companionStatus = GetCompanionManager().GetCompanionStatus(*templateId_);
    if (!companionStatus.has_value()) {
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

    if (TryRefreshToken(*companionStatus, errorGuard)) {
        return true;
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

void HostIssueTokenRequest::OnConnected()
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    HostPreIssueToken();
}

void HostIssueTokenRequest::HostPreIssueToken()
{
    ENSURE_OR_RETURN_DESC(GetDescription(), templateId_.has_value());
    HostPreIssueTokenInput input = {};
    input.requestId = GetRequestId();
    input.templateId = *templateId_;
    input.fwkUnlockMsg = fwkUnlockMsg_;
    HostPreIssueTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().HostPreIssueToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostPreIssueToken failed ret=%{public}d", GetDescription(), ret);
        CompleteWithError(ret);
        return;
    }
    needCancelIssueToken_ = true;

    bool sendRet = SendPreIssueTokenRequest(output.preIssueTokenRequest);
    if (!sendRet) {
        IAM_LOGE("%{public}s SendPreIssueTokenRequest failed", GetDescription());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
}

bool HostIssueTokenRequest::SendPreIssueTokenRequest(const std::vector<uint8_t> &preIssueTokenRequest)
{
    DeviceKey hostDeviceKey = {};
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), localDeviceKey.has_value(), false);
    hostDeviceKey = localDeviceKey.value();
    hostDeviceKey.deviceUserId = hostUserId_;
    PreIssueTokenRequest requestMsg = { .hostDeviceKey = hostDeviceKey,
        .companionUserId = companionUserId_,
        .extraInfo = preIssueTokenRequest };
    Attributes request = {};
    EncodePreIssueTokenRequest(requestMsg, request);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::PRE_ISSUE_TOKEN, request,
        [weakSelf = weak_from_this()](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandlePreIssueTokenReply(message);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return false;
    }
    return true;
}

void HostIssueTokenRequest::HandlePreIssueTokenReply(const Attributes &message)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyOpt = DecodePreIssueTokenReply(message);
    ENSURE_OR_RETURN_DESC(GetDescription(), replyOpt.has_value());
    const auto &reply = *replyOpt;
    if (reply.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s pre issue token failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(reply.result));
        errorGuard.UpdateErrorCode(reply.result);
        return;
    }

    HostBeginIssueTokenInput input = {};
    input.requestId = GetRequestId();
    input.secureProtocolId = secureProtocolId_;
    input.preIssueTokenReply = reply.extraInfo;
    HostBeginIssueTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().HostBeginIssueToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostBeginIssueToken failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }
    needCancelIssueToken_ = true;

    bool sendRet = SendIssueTokenRequest(output.issueTokenRequest);
    if (!sendRet) {
        IAM_LOGE("%{public}s SendIssueTokenRequest failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

bool HostIssueTokenRequest::SendIssueTokenRequest(const std::vector<uint8_t> &issueTokenRequest)
{
    DeviceKey hostDeviceKey = {};
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), localDeviceKey.has_value(), false);
    hostDeviceKey = localDeviceKey.value();
    hostDeviceKey.deviceUserId = hostUserId_;
    IssueTokenRequest requestMsg = { .hostDeviceKey = hostDeviceKey,
        .companionUserId = companionUserId_,
        .extraInfo = issueTokenRequest };
    Attributes request = {};
    EncodeIssueTokenRequest(requestMsg, request);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::ISSUE_TOKEN, request,
        [weakSelf = weak_from_this()](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleIssueTokenReply(message);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return false;
    }
    return true;
}

ResultCode HostIssueTokenRequest::CallSecurityAgentEndIssueToken(const std::vector<uint8_t> &issueTokenReply, Atl &atl)
{
    HostEndIssueTokenInput input = {};
    input.requestId = GetRequestId();
    input.secureProtocolId = secureProtocolId_;
    input.issueTokenReply = issueTokenReply;
    HostEndIssueTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().HostEndIssueToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostEndIssueToken failed ret=%{public}d", GetDescription(), ret);
        return ret;
    }
    IAM_LOGI("%{public}s HostEndIssueToken success atl=%{public}d", GetDescription(), output.atl);
    atl = output.atl;
    return ResultCode::SUCCESS;
}

void HostIssueTokenRequest::HandleIssueTokenReply(const Attributes &message)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyOpt = DecodeIssueTokenReply(message);
    ENSURE_OR_RETURN_DESC(GetDescription(), replyOpt.has_value());
    const auto &reply = *replyOpt;
    if (reply.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s issue token failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(reply.result));
        errorGuard.UpdateErrorCode(reply.result);
        return;
    }
    Atl atl = 0;
    ResultCode ret = CallSecurityAgentEndIssueToken(reply.extraInfo, atl);
    needCancelIssueToken_ = false;
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostEndIssueToken failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }
    eventCollector_.SetAtl(atl);
    ENSURE_OR_RETURN_DESC(GetDescription(), templateId_.has_value());
    bool setTokenAtlRet = GetCompanionManager().SetCompanionTokenAuthAtl(*templateId_, atl);
    if (!setTokenAtlRet) {
        IAM_LOGE("%{public}s SetCompanionTokenAuthAtl failed", GetDescription());
    }
    errorGuard.Cancel();
    CompleteWithSuccess();
}

std::weak_ptr<OutboundRequest> HostIssueTokenRequest::GetWeakPtr()
{
    return weak_from_this();
}

bool HostIssueTokenRequest::TryRefreshToken(const CompanionStatus &companionStatus, ErrorGuard &errorGuard)
{
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), templateId_.has_value(), false);
    if (!companionStatus.companionDeviceStatus.refreshToken || !companionStatus.tokenAuthAtl.has_value()) {
        IAM_LOGI("%{public}s skip token refresh: refreshToken=%{public}d, hasTokenAuthAtl=%{public}d", GetDescription(),
            companionStatus.companionDeviceStatus.refreshToken, companionStatus.tokenAuthAtl.has_value());
        return false;
    }

    HostRefreshTokenInput input = {};
    input.templateId = *templateId_;
    input.fwkMsg = fwkUnlockMsg_;
    HostRefreshTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().HostRefreshToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGI("%{public}s HostRefreshToken failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    if (output.needReissue) {
        IAM_LOGI("%{public}s needs reissue", GetDescription());
        return false;
    }

    IAM_LOGI("%{public}s token still valid (atl=%{public}d), refresh", GetDescription(), output.cachedAtl);
    eventCollector_.SetAtl(output.cachedAtl);
    bool setTokenAtlRet = GetCompanionManager().SetCompanionTokenAuthAtl(*templateId_, output.cachedAtl);
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), setTokenAtlRet, false);
    errorGuard.Cancel();
    CompleteWithSuccess(TOKEN_REFRESH_SUCCESS);
    return true;
}

bool HostIssueTokenRequest::EnsureCompanionAuthMaintainActive(const DeviceKey &deviceKey, ErrorGuard &errorGuard)
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

void HostIssueTokenRequest::HandlePeerDeviceStatusChanged(const std::vector<DeviceStatus> &deviceStatusList)
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

void HostIssueTokenRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s: issue token request failed, result=%{public}d", GetDescription(), result);
    if (needCancelIssueToken_) {
        HostCancelIssueTokenInput input = { GetRequestId() };
        ResultCode ret = GetSecurityAgent().HostCancelIssueToken(input);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s HostCancelIssueToken failed ret=%{public}d", GetDescription(), ret);
        }
        needCancelIssueToken_ = false;
    }
    eventCollector_.Report(result);
    Destroy();
}

void HostIssueTokenRequest::CompleteWithSuccess(ResultCode result)
{
    IAM_LOGI("%{public}s complete with success, result=%{public}d", GetDescription(), result);
    eventCollector_.Report(result);
    Destroy();
}

uint32_t HostIssueTokenRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent HostIssueTokenRequest
}

bool HostIssueTokenRequest::CanStart(const std::vector<std::shared_ptr<IRequest>> &prevRequests) const
{
    if (CountSameType(prevRequests) >= GetMaxConcurrency()) {
        return false;
    }
    // Spec: HostIssueTokenRequest cannot run while HostTokenAuthRequest is active on the same device
    auto currentPeerDevice = GetPeerDeviceKey();
    for (const auto &req : prevRequests) {
        if (req != nullptr && req->GetRequestType() == RequestType::HOST_TOKEN_AUTH_REQUEST) {
            auto reqPeerDevice = req->GetPeerDeviceKey();
            if (currentPeerDevice.has_value() && reqPeerDevice.has_value() &&
                currentPeerDevice.value() == reqPeerDevice.value()) {
                IAM_LOGI("%{public}s: blocked by HostTokenAuth on same device", GetDescription());
                return false;
            }
        }
    }
    return true;
}

bool HostIssueTokenRequest::ShouldCancelOnNewRequest(const IRequest &newRequest,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostAddCompanionRequest preempts HostIssueTokenRequest
    if (newRequest.GetRequestType() == RequestType::HOST_ADD_COMPANION_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostAddCompanion", GetDescription());
        return true;
    }

    // Spec: new HostIssueTokenRequest to same device preempts existing one
    // Only preempt when both peerDeviceKeys are valid and equal
    if (newRequest.GetRequestType() == RequestType::HOST_ISSUE_TOKEN_REQUEST) {
        auto currentPeerDevice = GetPeerDeviceKey();
        auto newPeerDevice = newRequest.GetPeerDeviceKey();
        if (currentPeerDevice.has_value() && newPeerDevice.has_value() &&
            currentPeerDevice.value() == newPeerDevice.value()) {
            IAM_LOGI("%{public}s: preempted by new HostIssueToken to same device", GetDescription());
            return true;
        }
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
