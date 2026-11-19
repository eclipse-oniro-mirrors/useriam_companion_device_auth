/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "host_binding_signature_challenge_requester.h"

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "binding_signature_message.h"
#include "error_guard.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_BINDING_SIGNATURE_CHALLENGE_REQUESTER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
void RequestBindingSignatureChallenge(const std::string &connectionName, const UserKey &hostUserKey,
    const std::optional<UserKey> &companionUserKey, BindingSignatureChallengeCallback &&onResolved)
{
    ENSURE_OR_RETURN(onResolved != nullptr);
    IAM_LOGI("start, hostUserId:%{public}d, asserted companion user:%{public}d", hostUserKey.userId,
        companionUserKey.has_value() ? companionUserKey->userId : INVALID_USER_ID);

    ErrorGuard errorGuard([&onResolved](ResultCode code) { onResolved(code, {}); });

    GetBindingSignatureChallengeRequest challengeRequest = {};
    challengeRequest.hostDeviceKey.deviceUserId = hostUserKey.userId;
    challengeRequest.hostDeviceKey.deviceSubProfileId = hostUserKey.subProfileId;
    challengeRequest.companionUserKey = companionUserKey;

    Attributes challengeAttributes = {};
    EncodeGetBindingSignatureChallengeRequest(challengeRequest, challengeAttributes);
    auto callback = std::make_shared<BindingSignatureChallengeCallback>(onResolved);
    ENSURE_OR_RETURN(callback != nullptr);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(connectionName, MessageType::GET_BINDING_SIGNATURE_CHALLENGE,
        challengeAttributes, [callback](const Attributes &reply) {
            ENSURE_OR_RETURN(*callback != nullptr);
            ErrorGuard replyGuard([callback](ResultCode code) { (*callback)(code, {}); });
            auto replyOpt = DecodeGetBindingSignatureChallengeReply(reply);
            if (!replyOpt.has_value()) {
                IAM_LOGE("decode GET_BINDING_SIGNATURE_CHALLENGE reply failed");
                replyGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
                return;
            }
            if (replyOpt->result != ResultCode::SUCCESS) {
                IAM_LOGE("GET_BINDING_SIGNATURE_CHALLENGE reply error ret:%{public}d",
                    static_cast<int32_t>(replyOpt->result));
                replyGuard.UpdateErrorCode(replyOpt->result);
                return;
            }
            BindingSignatureChallengeResult challengeResult = {};
            challengeResult.companionUserKey = replyOpt->companionUserKey;
            challengeResult.challenge = replyOpt->challenge;
            replyGuard.Cancel();
            (*callback)(ResultCode::SUCCESS, challengeResult);
        });
    if (!sendRet) {
        IAM_LOGE("send GET_BINDING_SIGNATURE_CHALLENGE failed");
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
