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

#include "host_binding_proof_obtainer.h"

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "binding_signature_message.h"
#include "common_message.h"
#include "error_guard.h"
#include "security_agent.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_BINDING_PROOF_OBTAINER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
bool HostBindingProofObtainer::NeedBindingSignature(MessageType msgType, std::optional<TemplateId> templateId)
{
    return templateId.has_value() && IsBindingSignatureProtectedMessageType(msgType) &&
        GetCompanionManager().IsBindingSignatureRequired(*templateId);
}

bool HostBindingProofObtainer::HasProof() const
{
    return bindingProof_.has_value();
}

bool HostBindingProofObtainer::AttachProof(Attributes &request) const
{
    if (!bindingProof_.has_value()) {
        return false;
    }
    AttachBindingSignatureAttributes(bindingProof_->challenge, bindingProof_->signature, request);
    return true;
}

void HostBindingProofObtainer::ObtainAndAttach(const std::string &connectionName, TemplateId templateId,
    MessageType msgType, const std::shared_ptr<Attributes> &request, BindingProofReadyCallback &&onBindingProofReady)
{
    ENSURE_OR_RETURN(request != nullptr);
    ENSURE_OR_RETURN(onBindingProofReady != nullptr);
    IAM_LOGI("start, templateId:%{public}s msgType:0x%{public}x", GET_MASKED_NUM_STRING(templateId).c_str(),
        static_cast<uint32_t>(msgType));
    ErrorGuard errorGuard([&onBindingProofReady](ResultCode code) { onBindingProofReady(code); });
    auto hostUserKey = DecodeHostUserKey(*request);
    if (!hostUserKey.has_value()) {
        IAM_LOGE("decode host identity from request failed");
        errorGuard.UpdateErrorCode(ResultCode::INVALID_PARAMETERS);
        return;
    }
    std::optional<UserKey> companionUserKey = std::nullopt;
    if (HasCompanionUserKey(*request)) {
        companionUserKey = DecodeCompanionUserKey(*request);
        if (!companionUserKey.has_value()) {
            IAM_LOGE("decode companion identity from request failed");
            errorGuard.UpdateErrorCode(ResultCode::INVALID_PARAMETERS);
            return;
        }
    }

    RequestBindingSignatureChallenge(connectionName, *hostUserKey, companionUserKey,
        [weakSelf = weak_from_this(), templateId, request, onBindingProofReady](ResultCode resultCode,
            const BindingSignatureChallengeResult &challengeResult) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleChallengeResolved(templateId, request, resultCode, challengeResult, onBindingProofReady);
        });
    errorGuard.Cancel();
}

void HostBindingProofObtainer::HandleChallengeResolved(TemplateId templateId,
    const std::shared_ptr<Attributes> &request, ResultCode resultCode,
    const BindingSignatureChallengeResult &challengeResult, const BindingProofReadyCallback &onBindingProofReady)
{
    ENSURE_OR_RETURN(request != nullptr);
    ENSURE_OR_RETURN(onBindingProofReady != nullptr);
    ErrorGuard errorGuard([&onBindingProofReady](ResultCode code) { onBindingProofReady(code); });
    if (resultCode != ResultCode::SUCCESS) {
        IAM_LOGE("acquire binding signature challenge failed ret:%{public}d", static_cast<int32_t>(resultCode));
        errorGuard.UpdateErrorCode(resultCode);
        return;
    }

    auto companionStatus = GetCompanionManager().GetCompanionStatus(templateId);
    if (!companionStatus.has_value()) {
        IAM_LOGE("no local binding for templateId:%{public}s", GET_MASKED_NUM_STRING(templateId).c_str());
        errorGuard.UpdateErrorCode(ResultCode::NOT_ENROLLED);
        return;
    }

    const DeviceKey &companionDeviceKey = companionStatus->companionDeviceStatus.deviceKey;
    if (challengeResult.companionUserKey.userId != companionDeviceKey.deviceUserId ||
        challengeResult.companionUserKey.subProfileId != companionDeviceKey.deviceSubProfileId) {
        IAM_LOGE("reply identity does not match the local binding");
        errorGuard.UpdateErrorCode(ResultCode::TARGET_USER_MISMATCH);
        return;
    }

    HostBindingSignInput input = {};
    input.templateId = templateId;
    input.challenge = challengeResult.challenge;
    HostBindingSignOutput output = {};
    ResultCode ret = GetSecurityAgent().HostBindingSign(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("HostBindingSign failed ret:%{public}d", static_cast<int32_t>(ret));
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    bindingProof_ = BindingSignatureProof { challengeResult.challenge, output.signature };
    AttachBindingSignatureAttributes(bindingProof_->challenge, bindingProof_->signature, *request);
    errorGuard.Cancel();
    onBindingProofReady(ResultCode::SUCCESS);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
