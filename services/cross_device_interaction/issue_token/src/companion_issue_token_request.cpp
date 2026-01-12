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

#include "common_message.h"
#include "cross_device_comm_manager_impl.h"
#include "error_guard.h"
#include "host_binding_manager.h"
#include "issue_token_message.h"
#include "security_agent.h"
#include "singleton_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionIssueTokenRequest::CompanionIssueTokenRequest(const std::string &connectionName, const Attributes &request,
    OnMessageReply replyCallback, const DeviceKey &hostDeviceKey)
    : InboundRequest(RequestType::COMPANION_ISSUE_TOKEN_REQUEST, connectionName, hostDeviceKey),
      request_(request),
      preIssueTokenReplyCallback_(std::move(replyCallback))
{
}

bool CompanionIssueTokenRequest::OnStart(ErrorGuard &errorGuard)
{
    IAM_LOGI("%{public}s", GetDescription());

    if (!GetCrossDeviceCommManager().IsAuthMaintainActive()) {
        IAM_LOGE("%{public}s local auth maintain inactive", GetDescription());
        SendPreIssueTokenReply(ResultCode::GENERAL_ERROR, {});
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return false;
    }
    localDeviceStatusSubscription_ = GetCrossDeviceCommManager().SubscribeIsAuthMaintainActive(
        [weakSelf = std::weak_ptr<CompanionIssueTokenRequest>(shared_from_this())](bool isActive) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleAuthMaintainActiveChanged(isActive);
        });
    if (localDeviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe auth maintain active", GetDescription());
        SendPreIssueTokenReply(ResultCode::GENERAL_ERROR, {});
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
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
            [weakSelf = std::weak_ptr<CompanionIssueTokenRequest>(shared_from_this())](const Attributes &request,
                OnMessageReply &onMessageReply) {
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
    IAM_LOGI("%{public}s", GetDescription());
    PreIssueTokenRequest preIssueRequest = {};
    bool decodeReqRet = DecodePreIssueTokenRequest(request_, preIssueRequest);
    ENSURE_OR_RETURN_VAL(decodeReqRet, false);
    if (preIssueRequest.hostDeviceKey != PeerDeviceKey()) {
        IAM_LOGE("%{public}s host device key mismatch", GetDescription());
        return false;
    }
    companionUserId_ = preIssueRequest.companionUserId;
    preIssueTokenRequest_ = preIssueRequest.extraInfo;

    SecureProtocolId secureProtocolId = GetCrossDeviceCommManager().CompanionGetSecureProtocolId();
    ENSURE_OR_RETURN_VAL(secureProtocolId != SecureProtocolId::INVALID, false);
    secureProtocolId_ = secureProtocolId;

    auto hostBindingStatus = GetHostBindingManager().GetHostBindingStatus(companionUserId_, PeerDeviceKey());
    ENSURE_OR_RETURN_VAL(hostBindingStatus.has_value(), false);

    bindingId_ = hostBindingStatus->bindingId;

    CompanionPreIssueTokenInput input = {};
    input.requestId = GetRequestId();
    input.bindingId = bindingId_;
    input.secureProtocolId = secureProtocolId_;
    input.preIssueTokenRequest = preIssueTokenRequest_;

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

void CompanionIssueTokenRequest::SendPreIssueTokenReply(ResultCode result,
    const std::vector<uint8_t> &preIssueTokenReply)
{
    ENSURE_OR_RETURN(preIssueTokenReplyCallback_ != nullptr);

    Attributes reply = {};
    PreIssueTokenReply replyMsg = { .result = result, .extraInfo = preIssueTokenReply };
    bool encodeRet = EncodePreIssueTokenReply(replyMsg, reply);
    ENSURE_OR_RETURN(encodeRet);

    preIssueTokenReplyCallback_(reply);
}

void CompanionIssueTokenRequest::HandleIssueTokenMessage(const Attributes &request, OnMessageReply &onMessageReply)
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this, &onMessageReply](ResultCode code) {
        Attributes reply;
        IssueTokenReply replyMsg = { .result = code, .extraInfo = {} };
        EncodeIssueTokenReply(replyMsg, reply);
        onMessageReply(reply);
        CompleteWithError(code);
    });

    IssueTokenRequest issueRequest = {};
    bool decodeReqRet = DecodeIssueTokenRequest(request, issueRequest);
    ENSURE_OR_RETURN(decodeReqRet);

    std::vector<uint8_t> issueTokenReply;
    bool result = SecureAgentCompanionIssueToken(issueRequest.extraInfo, issueTokenReply);
    IssueTokenReply replyMsg = { .result = result ? ResultCode::SUCCESS : ResultCode::GENERAL_ERROR,
        .extraInfo = issueTokenReply };
    Attributes reply;
    EncodeIssueTokenReply(replyMsg, reply);
    onMessageReply(reply);
    if (!result) {
        IAM_LOGE("%{public}s SecureAgentCompanionIssueToken failed", GetDescription());
        return;
    }
    errorGuard.Cancel();
    CompleteWithSuccess();
}

bool CompanionIssueTokenRequest::SecureAgentCompanionIssueToken(const std::vector<uint8_t> &issueTokenRequest,
    std::vector<uint8_t> &issueTokenReply)
{
    IAM_LOGI("%{public}s", GetDescription());
    CompanionProcessIssueTokenInput input = { .requestId = GetRequestId(),
        .secureProtocolId = secureProtocolId_,
        .issueTokenRequest = issueTokenRequest };

    CompanionProcessIssueTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionProcessIssueToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionProcessIssueToken failed ret=%{public}d", GetDescription(), ret);
        return false;
    }

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
    return shared_from_this();
}

void CompanionIssueTokenRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s: receive issue token request failed, result=%{public}d", GetDescription(), result);
    localDeviceStatusSubscription_.reset();
    if (needCancelIssueToken_) {
        CompanionCancelIssueTokenInput input = { GetRequestId() };
        (void)GetSecurityAgent().CompanionCancelIssueToken(input);
        needCancelIssueToken_ = false;
    }
    Destroy();
}

void CompanionIssueTokenRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s: receive issue token request completed successfully", GetDescription());

    localDeviceStatusSubscription_.reset();
    Destroy();
}

uint32_t CompanionIssueTokenRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent CompanionIssueTokenRequest
}

bool CompanionIssueTokenRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    const std::optional<DeviceKey> &newPeerDevice, [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new CompanionIssueTokenRequest to same device preempts existing one
    if (newRequestType == RequestType::COMPANION_ISSUE_TOKEN_REQUEST && GetPeerDeviceKey() == newPeerDevice) {
        IAM_LOGI("%{public}s: preempted by new CompanionIssueToken to same device", GetDescription());
        return true;
    }

    return false;
}

void CompanionIssueTokenRequest::HandleAuthMaintainActiveChanged(bool isActive)
{
    if (isActive) {
        return;
    }
    IAM_LOGE("%{public}s local auth maintain inactive, cancel request", GetDescription());
    CompleteWithError(ResultCode::GENERAL_ERROR);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
