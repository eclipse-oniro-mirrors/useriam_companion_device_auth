/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "companion_get_binding_signature_challenge_handler.h"

#include <algorithm>

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "binding_signature_message.h"
#include "cda_scope_guard.h"
#include "error_guard.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_COMPANION_GET_BINDING_SIGNATURE_CHALLENGE_HANDLER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

CompanionGetBindingSignatureChallengeHandler::CompanionGetBindingSignatureChallengeHandler()
    : SyncIncomingMessageHandler(MessageType::GET_BINDING_SIGNATURE_CHALLENGE)
{
}

void CompanionGetBindingSignatureChallengeHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    IAM_LOGI("start");
    LogTraceGuard guard;

    auto localProfile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    std::string advertisedProtocols;
    for (const auto &protocol : localProfile.companionProtocols) {
        advertisedProtocols += std::to_string(static_cast<uint16_t>(protocol)) + ",";
    }
    IAM_LOGI("challenge served on advertised companion protocols: %{public}s", advertisedProtocols.c_str());

    ErrorGuard errorGuard([&reply](ResultCode result) {
        GetBindingSignatureChallengeReply challengeReply = {};
        challengeReply.result = result;
        EncodeGetBindingSignatureChallengeReply(challengeReply, reply);
    });

    auto challengeRequestOpt = DecodeGetBindingSignatureChallengeRequest(request);
    if (!challengeRequestOpt.has_value()) {
        IAM_LOGE("DecodeGetBindingSignatureChallengeRequest failed");
        errorGuard.UpdateErrorCode(ResultCode::INVALID_PARAMETERS);
        return;
    }

    UserKey companionUserKey;
    if (ResultCode identityRet = ResolveChallengeIdentity(*challengeRequestOpt, companionUserKey);
        identityRet != ResultCode::SUCCESS) {
        errorGuard.UpdateErrorCode(identityRet);
        return;
    }
    const std::string &connectionName = challengeRequestOpt->connectionName;

    CompanionGenerateBindingSignatureChallengeOutput output = {};
    ResultCode ret = IssueChallenge(connectionName, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("IssueChallenge failed ret:%{public}d", static_cast<int32_t>(ret));
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    GetBindingSignatureChallengeReply challengeReply = {};
    challengeReply.result = ResultCode::SUCCESS;
    challengeReply.companionUserKey = companionUserKey;
    challengeReply.challenge = output.challenge;
    EncodeGetBindingSignatureChallengeReply(challengeReply, reply);
    errorGuard.Cancel();
    IAM_LOGI("success");
}

ResultCode CompanionGetBindingSignatureChallengeHandler::ResolveChallengeIdentity(
    const GetBindingSignatureChallengeRequest &challengeRequest, UserKey &companionUserKey)
{
    UserKey activeUserKey = GetUserKeyManager().GetUnlockedActiveUserkey();
    if (activeUserKey.userId == INVALID_USER_ID) {
        return ResultCode::TARGET_USER_MISMATCH;
    }
    if (challengeRequest.companionUserKey.has_value() && *challengeRequest.companionUserKey != activeUserKey) {
        IAM_LOGE("companion user key mismatch with local unlocked active user userId:%{public}d",
            challengeRequest.companionUserKey->userId);
        return ResultCode::TARGET_USER_MISMATCH;
    }
    companionUserKey = activeUserKey;
    if (challengeRequest.companionUserKey.has_value()) {
        auto hostBindingStatus =
            GetHostBindingManager().GetHostBindingStatus(companionUserKey, challengeRequest.hostDeviceKey);
        if (!hostBindingStatus.has_value()) {
            IAM_LOGE("asserted identity has no host binding, hostUserId:%{public}d",
                challengeRequest.hostDeviceKey.deviceUserId);
            return ResultCode::NOT_ENROLLED;
        }
    }
    return ResultCode::SUCCESS;
}

ResultCode CompanionGetBindingSignatureChallengeHandler::IssueChallenge(const std::string &connectionName,
    CompanionGenerateBindingSignatureChallengeOutput &output)
{
    ResultCode ret = GetSecurityAgent().CompanionGenerateBindingSignatureChallenge(output);
    ENSURE_OR_RETURN_VAL(ret == ResultCode::SUCCESS, ret);
    if (output.challenge.size() != BINDING_SIGNATURE_CHALLENGE_LEN) {
        IAM_LOGE("challenge length invalid len:%{public}zu", output.challenge.size());
        return ResultCode::GENERAL_ERROR;
    }

    ScopeGuard challengeGuard([this, &output]() { PurgeChallenge(output.challenge); });

    constexpr size_t connectionCapacity = 100;
    std::vector<uint8_t> staleChallenge;
    auto it = std::find_if(connections_.begin(), connections_.end(),
        [&connectionName](const ConnectionEntry &entry) { return entry.connectionName == connectionName; });
    if (it != connections_.end()) {
        staleChallenge = std::move(it->challenge);
        connections_.erase(it);
    } else if (connections_.size() >= connectionCapacity) {
        IAM_LOGI("binding signature connection records full, evict oldest: %{public}zu", connections_.size());
        staleChallenge = std::move(connections_.front().challenge);
        connections_.erase(connections_.begin());
    }
    PurgeChallenge(staleChallenge);

    auto subscription = GetCrossDeviceCommManager().SubscribeConnectionStatus(connectionName,
        [weakHandler = weak_from_this()](const std::string &connName, ConnectionStatus status,
            const std::string &reason) {
            auto baseHandler = weakHandler.lock();
            ENSURE_OR_RETURN(baseHandler != nullptr);
            auto handler = std::static_pointer_cast<CompanionGetBindingSignatureChallengeHandler>(baseHandler);
            handler->HandleConnectionStatus(connName, status, reason);
        });
    ENSURE_OR_RETURN_VAL(subscription != nullptr, ResultCode::GENERAL_ERROR);
    ConnectionEntry entry = { connectionName, output.challenge, std::move(subscription) };
    connections_.push_back(std::move(entry));
    challengeGuard.Cancel();
    return ResultCode::SUCCESS;
}

void CompanionGetBindingSignatureChallengeHandler::HandleConnectionStatus(const std::string &connName,
    ConnectionStatus status, const std::string &reason)
{
    auto it = std::find_if(connections_.begin(), connections_.end(),
        [&connName](const ConnectionEntry &entry) { return entry.connectionName == connName; });
    if (status != ConnectionStatus::DISCONNECTED || it == connections_.end()) {
        return;
    }
    IAM_LOGI("connection %{public}s disconnected, purge binding signature challenge, reason:%{public}s",
        connName.c_str(), reason.c_str());
    std::vector<uint8_t> staleChallenge = std::move(it->challenge);
    connections_.erase(it);
    PurgeChallenge(staleChallenge);
}

void CompanionGetBindingSignatureChallengeHandler::PurgeChallenge(const std::vector<uint8_t> &challenge)
{
    if (challenge.empty()) {
        return;
    }
    ResultCode ret = GetSecurityAgent().CompanionPurgeBindingSignatureChallenge(challenge);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("CompanionPurgeBindingSignatureChallenge failed ret:%{public}d", static_cast<int32_t>(ret));
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
