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

#include "companion_issue_token_request.h"

#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "common_message.h"
#include "error_guard.h"
#include "host_binding_manager.h"
#include "iam_log_tracer.h"
#include "issue_token_message.h"
#include "security_agent.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_COMPANION_ISSUE_TOKEN_REQUEST

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionIssueTokenRequest::CompanionIssueTokenRequest(const std::string &connectionName, const Attributes &request,
    OnMessageReply &&replyCallback, const DeviceKey &hostDeviceKey)
    : InboundRequest(RequestType::COMPANION_ISSUE_TOKEN_REQUEST, connectionName, hostDeviceKey),
      request_(request),
      preIssueTokenReplyCallback_(std::move(replyCallback))
{
}

bool CompanionIssueTokenRequest::OnStart(ErrorGuard &errorGuard)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());

    if (!GetCrossDeviceCommManager().IsAuthMaintainActive()) {
        IAM_LOGE("%{public}s local auth maintain inactive", GetDescription());
        SendPreIssueTokenReply(ResultCode::GENERAL_ERROR, {});
        return false;
    }
    localDeviceStatusSubscription_ =
        GetCrossDeviceCommManager().SubscribeIsAuthMaintainActive([weakSelf = weak_from_this()](bool isActive) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleAuthMaintainActiveChanged(isActive);
        });
    if (localDeviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe auth maintain active", GetDescription());
        SendPreIssueTokenReply(ResultCode::GENERAL_ERROR, {});
        return false;
    }

    std::vector<uint8_t> preIssueTokenReply;
    bool preIssueRet = CompanionPreIssueToken(preIssueTokenReply);
    if (!preIssueRet) {
        IAM_LOGE("%{public}s CompanionPreIssueToken failed", GetDescription());
        SendPreIssueTokenReply(ResultCode::GENERAL_ERROR, {});
        return false;
    }

    issueTokenSubscription_ =
        GetCrossDeviceCommManager().SubscribeMessage(GetConnectionName(), MessageType::ISSUE_TOKEN,
            [weakSelf = weak_from_this()](const Attributes &request, OnMessageReply &onMessageReply) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleIssueTokenMessage(request, onMessageReply);
            });
    if (issueTokenSubscription_ == nullptr) {
        IAM_LOGE("%{public}s subscribe issue token failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return false;
    }

    SendPreIssueTokenReply(ResultCode::SUCCESS, preIssueTokenReply);
    errorGuard.Cancel();
    return true;
}

bool CompanionIssueTokenRequest::CompanionPreIssueToken(std::vector<uint8_t> &preIssueTokenReply)
{
    IAM_LOGI("%{public}s start", GetDescription());
    auto preIssueRequestOpt = DecodePreIssueTokenRequest(request_);
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), preIssueRequestOpt.has_value(), false);
    const auto &preIssueRequest = *preIssueRequestOpt;
    if (preIssueRequest.hostDeviceKey != PeerDeviceKey()) {
        IAM_LOGE("%{public}s host device key mismatch", GetDescription());
        return false;
    }
    companionUserId_ = preIssueRequest.companionUserId;

    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), localDeviceKey.has_value(), false);
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), companionUserId_ == localDeviceKey->deviceUserId, false);

    preIssueTokenRequest_ = preIssueRequest.extraInfo;

    eventCollector_.SetHostDeviceKey(PeerDeviceKey());
    eventCollector_.SetCompanionUserId(companionUserId_);
    eventCollector_.SetConnectionName(GetConnectionName());

    SecureProtocolId secureProtocolId = QuerySecureProtocolId();
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), secureProtocolId != SecureProtocolId::INVALID, false);
    secureProtocolId_ = secureProtocolId;

    auto bindingIdOpt = QueryBindingIdFromHostBinding();
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), bindingIdOpt.has_value(), false);
    bindingId_ = *bindingIdOpt;
    desc_.SetBindingId(bindingId_);
    eventCollector_.SetBindingId(bindingId_);

    return CallSecurityAgentPreIssueToken(preIssueTokenReply);
}

SecureProtocolId CompanionIssueTokenRequest::QuerySecureProtocolId()
{
    return GetCrossDeviceCommManager().CompanionGetSecureProtocolId();
}

std::optional<BindingId> CompanionIssueTokenRequest::QueryBindingIdFromHostBinding()
{
    auto hostBindingStatus = GetHostBindingManager().GetHostBindingStatus(companionUserId_, PeerDeviceKey());
    if (!hostBindingStatus.has_value()) {
        IAM_LOGE("%{public}s GetHostBindingStatus failed", GetDescription());
        return std::nullopt;
    }
    return hostBindingStatus->bindingId;
}

bool CompanionIssueTokenRequest::CallSecurityAgentPreIssueToken(std::vector<uint8_t> &preIssueTokenReply)
{
    auto input = BuildCompanionPreIssueTokenInput();
    CompanionPreIssueTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionPreIssueToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionPreIssueToken failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    needCancelIssueToken_ = true;
    preIssueTokenReply = output.preIssueTokenReply;
    return true;
}

CompanionPreIssueTokenInput CompanionIssueTokenRequest::BuildCompanionPreIssueTokenInput() const
{
    CompanionPreIssueTokenInput input = {};
    input.requestId = GetRequestId();
    input.bindingId = bindingId_;
    input.secureProtocolId = secureProtocolId_;
    input.preIssueTokenRequest = preIssueTokenRequest_;
    return input;
}

void CompanionIssueTokenRequest::SendPreIssueTokenReply(ResultCode result,
    const std::vector<uint8_t> &preIssueTokenReply)
{
    ENSURE_OR_RETURN_DESC(GetDescription(), preIssueTokenReplyCallback_ != nullptr);

    Attributes reply = {};
    PreIssueTokenReply replyMsg = { .result = result, .extraInfo = preIssueTokenReply };
    EncodePreIssueTokenReply(replyMsg, reply);

    preIssueTokenReplyCallback_(reply);
}

void CompanionIssueTokenRequest::HandleIssueTokenMessage(const Attributes &request, OnMessageReply &onMessageReply)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    ENSURE_OR_RETURN_DESC(GetDescription(), onMessageReply != nullptr);
    ErrorGuard errorGuard([this, &onMessageReply](ResultCode code) {
        Attributes reply;
        IssueTokenReply replyMsg = { .result = code, .extraInfo = {} };
        EncodeIssueTokenReply(replyMsg, reply);
        onMessageReply(reply);
        CompleteWithError(code);
    });

    auto issueRequestOpt = DecodeIssueTokenRequest(request);
    ENSURE_OR_RETURN_DESC(GetDescription(), issueRequestOpt.has_value());
    const auto &issueRequest = *issueRequestOpt;

    std::vector<uint8_t> issueTokenReply;
    bool success = SecureAgentCompanionIssueToken(issueRequest.extraInfo, issueTokenReply);
    IssueTokenReply replyMsg = { .result = success ? ResultCode::SUCCESS : ResultCode::GENERAL_ERROR,
        .extraInfo = issueTokenReply };
    Attributes reply;
    EncodeIssueTokenReply(replyMsg, reply);
    onMessageReply(reply);
    if (!success) {
        IAM_LOGE("%{public}s SecureAgentCompanionIssueToken failed", GetDescription());
        return;
    }
    errorGuard.Cancel();
    CompleteWithSuccess();
}

bool CompanionIssueTokenRequest::SecureAgentCompanionIssueToken(const std::vector<uint8_t> &issueTokenRequest,
    std::vector<uint8_t> &issueTokenReply)
{
    IAM_LOGI("%{public}s start", GetDescription());
    CompanionProcessIssueTokenInput input = { .requestId = GetRequestId(),
        .secureProtocolId = secureProtocolId_,
        .issueTokenRequest = issueTokenRequest };

    CompanionProcessIssueTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionProcessIssueToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionProcessIssueToken failed ret=%{public}d", GetDescription(), ret);
        return false;
    }

    eventCollector_.SetAtl(output.atl);
    issueTokenReply.swap(output.issueTokenReply);
    bool setTokenValidRet = GetHostBindingManager().SetHostBindingTokenValid(bindingId_, true);
    if (!setTokenValidRet) {
        IAM_LOGE("%{public}s SetHostBindingTokenValid failed", GetDescription());
    }
    needCancelIssueToken_ = false;
    return true;
}

std::weak_ptr<InboundRequest> CompanionIssueTokenRequest::GetWeakPtr()
{
    return weak_from_this();
}

void CompanionIssueTokenRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s: issue token request failed, result=%{public}d", GetDescription(), result);
    localDeviceStatusSubscription_.reset();
    if (needCancelIssueToken_) {
        CompanionCancelIssueTokenInput input = { GetRequestId() };
        (void)GetSecurityAgent().CompanionCancelIssueToken(input);
        needCancelIssueToken_ = false;
    }
    eventCollector_.Report(result);
    Destroy();
}

void CompanionIssueTokenRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s: issue token request completed successfully", GetDescription());
    localDeviceStatusSubscription_.reset();
    eventCollector_.Report(ResultCode::SUCCESS);
    Destroy();
}

uint32_t CompanionIssueTokenRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent CompanionIssueTokenRequest
}

bool CompanionIssueTokenRequest::ShouldCancelOnNewRequest(const IRequest &newRequest,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new CompanionIssueTokenRequest to same device preempts existing one
    if (newRequest.GetRequestType() == RequestType::COMPANION_ISSUE_TOKEN_REQUEST &&
        GetPeerDeviceKey() == newRequest.GetPeerDeviceKey()) {
        IAM_LOGI("%{public}s: preempted by new CompanionIssueToken to same device", GetDescription());
        return true;
    }

    return false;
}

void CompanionIssueTokenRequest::HandleAuthMaintainActiveChanged(bool isActive)
{
    LogTraceGuard guard;
    if (isActive) {
        return;
    }
    IAM_LOGE("%{public}s local auth maintain inactive, cancel request", GetDescription());
    CompleteWithError(ResultCode::GENERAL_ERROR);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
