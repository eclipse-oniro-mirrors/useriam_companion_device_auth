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

#include "companion_manager.h"
#include "companion_pre_issue_token_handler.h"
#include "cross_device_comm_manager_impl.h"
#include "error_guard.h"
#include "issue_token_message.h"
#include "security_agent.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostIssueTokenRequest::HostIssueTokenRequest(UserId hostUserId, TemplateId templateId,
    const std::vector<uint8_t> &fwkUnlockMsg)
    : OutboundRequest(RequestType::HOST_ISSUE_TOKEN_REQUEST, 0, DEFAULT_REQUEST_TIMEOUT_MS),
      hostUserId_(hostUserId),
      templateId_(templateId),
      fwkUnlockMsg_(fwkUnlockMsg)
{
}

bool HostIssueTokenRequest::OnStart(ErrorGuard &errorGuard)
{
    auto companionStatus = GetCompanionManager().GetCompanionStatus(templateId_);
    if (!companionStatus.has_value()) {
        return false;
    }

    const DeviceKey &companionDeviceKey = companionStatus->companionDeviceStatus.deviceKey;
    SetPeerDeviceKey(companionDeviceKey);
    if (!EnsureCompanionAuthMaintainActive(companionDeviceKey, errorGuard)) {
        return false;
    }

    companionUserId_ = companionStatus->companionDeviceStatus.deviceKey.deviceUserId;
    auto secureProtocolOpt = GetCrossDeviceCommManager().HostGetSecureProtocolId(companionDeviceKey);
    if (!secureProtocolOpt.has_value()) {
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return false;
    }
    secureProtocolId_ = secureProtocolOpt.value();
    if (!OpenConnection()) {
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return false;
    }
    return true;
}

void HostIssueTokenRequest::OnConnected()
{
    IAM_LOGI("%{public}s", GetDescription());
    HostPreIssueToken();
}

void HostIssueTokenRequest::HostPreIssueToken()
{
    HostPreIssueTokenInput input = {};
    input.requestId = GetRequestId();
    input.templateId = templateId_;
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
    if (localDeviceKey.has_value()) {
        hostDeviceKey = *localDeviceKey;
    }
    hostDeviceKey.deviceUserId = hostUserId_;
    PreIssueTokenRequest requestMsg = { .hostDeviceKey = hostDeviceKey,
        .companionUserId = companionUserId_,
        .extraInfo = preIssueTokenRequest };
    Attributes request = {};
    bool encodeRet = EncodePreIssueTokenRequest(requestMsg, request);
    ENSURE_OR_RETURN_VAL(encodeRet, false);

    auto weakSelf = std::weak_ptr<HostIssueTokenRequest>(shared_from_this());
    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::PRE_ISSUE_TOKEN, request,
        [weakSelf](const Attributes &message) {
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
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyOpt = DecodePreIssueTokenReply(message);
    ENSURE_OR_RETURN(replyOpt.has_value());
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
    if (localDeviceKey.has_value()) {
        hostDeviceKey = *localDeviceKey;
    }
    hostDeviceKey.deviceUserId = hostUserId_;
    IssueTokenRequest requestMsg = { .hostDeviceKey = hostDeviceKey,
        .companionUserId = companionUserId_,
        .extraInfo = issueTokenRequest };
    Attributes request = {};
    bool encodeRet = EncodeIssueTokenRequest(requestMsg, request);
    ENSURE_OR_RETURN_VAL(encodeRet, false);

    auto weakSelf = std::weak_ptr<HostIssueTokenRequest>(shared_from_this());
    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::ISSUE_TOKEN, request,
        [weakSelf](const Attributes &message) {
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

void HostIssueTokenRequest::HandleIssueTokenReply(const Attributes &message)
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyOpt = DecodeIssueTokenReply(message);
    ENSURE_OR_RETURN(replyOpt.has_value());
    const auto &reply = *replyOpt;
    if (reply.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s issue token failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(reply.result));
        errorGuard.UpdateErrorCode(reply.result);
        return;
    }
    HostEndIssueTokenInput input = {};
    input.requestId = GetRequestId();
    input.secureProtocolId = secureProtocolId_;
    input.issueTokenReply = reply.extraInfo;
    HostEndIssueTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().HostEndIssueToken(input, output);
    needCancelIssueToken_ = false;
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostEndIssueToken failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }
    IAM_LOGI("%{public}s HostEndIssueToken success atl=%{public}d", GetDescription(), output.atl);
    bool setTokenAtlRet = GetCompanionManager().SetCompanionTokenAtl(templateId_, output.atl);
    if (!setTokenAtlRet) {
        IAM_LOGE("%{public}s SetCompanionTokenAtl failed", GetDescription());
    }
    errorGuard.Cancel();
    CompleteWithSuccess();
}

std::weak_ptr<OutboundRequest> HostIssueTokenRequest::GetWeakPtr()
{
    return shared_from_this();
}

bool HostIssueTokenRequest::EnsureCompanionAuthMaintainActive(const DeviceKey &deviceKey, ErrorGuard &errorGuard)
{
    auto deviceStatus = GetCrossDeviceCommManager().GetDeviceStatus(deviceKey);
    if (!deviceStatus.has_value()) {
        IAM_LOGE("%{public}s failed to get device status", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return false;
    }
    if (!deviceStatus->isAuthMaintainActive) {
        IAM_LOGE("%{public}s device not in auth maintain active state", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return false;
    }
    deviceStatusSubscription_ = GetCrossDeviceCommManager().SubscribeDeviceStatus(deviceKey,
        [weakSelf = std::weak_ptr<HostIssueTokenRequest>(shared_from_this())](
            const std::vector<DeviceStatus> &deviceStatusList) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandlePeerDeviceStatusChanged(deviceStatusList);
        });
    if (deviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe device status", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return false;
    }
    return true;
}

void HostIssueTokenRequest::HandlePeerDeviceStatusChanged(const std::vector<DeviceStatus> &deviceStatusList)
{
    auto peerDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN(peerDeviceKey.has_value());
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
    Destroy();
}

void HostIssueTokenRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    Destroy();
}

uint32_t HostIssueTokenRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent HostIssueTokenRequest
}

bool HostIssueTokenRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    const std::optional<DeviceKey> &newPeerDevice, [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostAddCompanionRequest preempts HostIssueTokenRequest
    if (newRequestType == RequestType::HOST_ADD_COMPANION_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostAddCompanion", GetDescription());
        return true;
    }

    // Spec: new HostIssueTokenRequest to same device preempts existing one
    if (newRequestType == RequestType::HOST_ISSUE_TOKEN_REQUEST && GetPeerDeviceKey() == newPeerDevice) {
        IAM_LOGI("%{public}s: preempted by new HostIssueToken to same device", GetDescription());
        return true;
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
