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

#include "companion_delegate_auth_request.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "common_message.h"
#include "cross_device_comm_manager_impl.h"
#include "delegate_auth_message.h"
#include "error_guard.h"
#include "host_binding_manager.h"
#include "security_agent.h"
#include "service_common.h"
#include "service_converter.h"
#include "singleton_manager.h"
#include "user_auth_adapter.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionDelegateAuthRequest::CompanionDelegateAuthRequest(const std::string &connectionName, int32_t companionUserId,
    const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &startDelegateAuthRequest)
    : InboundRequest(RequestType::COMPANION_DELEGATE_AUTH_REQUEST, connectionName, hostDeviceKey),
      companionUserId_(companionUserId),
      startDelegateAuthRequest_(startDelegateAuthRequest)
{
}

CompanionDelegateAuthRequest::~CompanionDelegateAuthRequest()
{
}

std::weak_ptr<InboundRequest> CompanionDelegateAuthRequest::GetWeakPtr()
{
    return shared_from_this();
}

bool CompanionDelegateAuthRequest::OnStart(ErrorGuard &errorGuard)
{
    IAM_LOGI("%{public}s start", GetDescription());

    hostDeviceKey_ = PeerDeviceKey();

    secureProtocolId_ = GetCrossDeviceCommManager().CompanionGetSecureProtocolId();
    ENSURE_OR_RETURN_VAL(secureProtocolId_ != SecureProtocolId::INVALID, false);

    bool ret = CompanionBeginDelegateAuth();
    if (!ret) {
        return false;
    }
    errorGuard.Cancel();
    return true;
}

bool CompanionDelegateAuthRequest::CompanionBeginDelegateAuth()
{
    IAM_LOGI("%{public}s start", GetDescription());
    uint64_t challenge = 0;
    Atl atl = 0;
    bool ret = SecureAgentBeginDelegateAuth(challenge, atl);
    ENSURE_OR_RETURN_VAL(ret, false);

    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_VAL(localDeviceKey.has_value(), false);

    auto weakSelf = std::weak_ptr<CompanionDelegateAuthRequest>(shared_from_this());
    AuthResultCallback callback = [weakSelf](int32_t result, const std::vector<uint8_t> &token) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        ResultCode resultCode = (result == ResultCode::SUCCESS) ? ResultCode::SUCCESS : ResultCode::GENERAL_ERROR;
        self->HandleDelegateAuthResult(resultCode, token);
    };

    uint64_t contextId = GetUserAuthAdapter().BeginDelegateAuth(localDeviceKey->deviceUserId,
        ConvertUint64ToUint8Vec(challenge), static_cast<uint32_t>(atl), callback);
    ENSURE_OR_RETURN_VAL(contextId != 0, false);
    contextId_ = contextId;
    return true;
}

bool CompanionDelegateAuthRequest::SecureAgentBeginDelegateAuth(uint64_t &challenge, Atl &atl)
{
    auto hostBindingStatus = GetHostBindingManager().GetHostBindingStatus(companionUserId_, hostDeviceKey_);
    ENSURE_OR_RETURN_VAL(hostBindingStatus.has_value(), false);
    int32_t hostBindingId = hostBindingStatus->bindingId;

    CompanionDelegateAuthBeginInput input = {};
    input.requestId = GetRequestId();
    input.bindingId = hostBindingId;
    input.secureProtocolId = secureProtocolId_;
    input.startDelegateAuthRequest = startDelegateAuthRequest_;
    CompanionDelegateAuthBeginOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionBeginDelegateAuth(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionBeginDelegateAuth failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    challenge = output.challenge;
    atl = output.atl;
    return true;
}

void CompanionDelegateAuthRequest::HandleDelegateAuthResult(ResultCode resultCode, const std::vector<uint8_t> &token)
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    IAM_LOGI("%{public}s start", GetDescription());
    contextId_.reset();

    std::vector<uint8_t> delegateAuthResult;
    bool result = SecurityAgentEndDelegateAuth(resultCode, token, delegateAuthResult);
    if (!result) {
        IAM_LOGE("%{public}s SecurityAgentEndDelegateAuth failed", GetDescription());
        resultCode = ResultCode::GENERAL_ERROR;
    }

    bool sendResult = SendDelegateAuthResult(resultCode, delegateAuthResult);
    if (!sendResult) {
        IAM_LOGE("%{public}s SendDelegateAuthResult failed", GetDescription());
        return;
    }
    errorGuard.Cancel();
}

bool CompanionDelegateAuthRequest::SendDelegateAuthResult(ResultCode resultCode,
    const std::vector<uint8_t> &delegateAuthResult)
{
    SendDelegateAuthResultRequest requestMsg = { .result = resultCode, .extraInfo = delegateAuthResult };
    Attributes request = {};
    bool encodeRet = EncodeSendDelegateAuthResultRequest(requestMsg, request);
    ENSURE_OR_RETURN_VAL(encodeRet, false);

    auto weakSelf = std::weak_ptr<CompanionDelegateAuthRequest>(shared_from_this());
    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::SEND_DELEGATE_AUTH_RESULT,
        request, [weakSelf](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleSendDelegateAuthResultReply(message);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return false;
    }
    return true;
}

bool CompanionDelegateAuthRequest::SecurityAgentEndDelegateAuth(ResultCode resultCode,
    const std::vector<uint8_t> &authToken, std::vector<uint8_t> &delegateAuthResult)
{
    IAM_LOGI("%{public}s result=%{public}d", GetDescription(), resultCode);

    CompanionDelegateAuthEndInput input = {};
    input.requestId = GetRequestId();
    input.resultCode = resultCode;
    input.authToken = authToken;
    CompanionDelegateAuthEndOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionEndDelegateAuth(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionEndDelegateAuth failed ret=%{public}d", GetDescription(), ret);
    }
    delegateAuthResult.swap(output.delegateAuthResult);
    return ret == ResultCode::SUCCESS;
}

void CompanionDelegateAuthRequest::HandleSendDelegateAuthResultReply(const Attributes &message)
{
    IAM_LOGI("%{public}s start", GetDescription());
    auto replyOpt = DecodeSendDelegateAuthResultReply(message);
    ENSURE_OR_RETURN(replyOpt.has_value());
    if (replyOpt->result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s delegate auth failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(replyOpt->result));
        CompleteWithError(replyOpt->result);
        return;
    }
    CompleteWithSuccess();
}

void CompanionDelegateAuthRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s complete with error: %{public}d", GetDescription(), result);
    if (contextId_.has_value()) {
        IAM_LOGI("%{public}s delegate auth not completed, cancelling", GetDescription());
        int32_t ret = GetUserAuthAdapter().CancelAuthentication(*contextId_);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s CancelAuthentication failed ret=%{public}d", GetDescription(), ret);
        }
        contextId_.reset();
    }
    Destroy();
}

void CompanionDelegateAuthRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    Destroy();
}

uint32_t CompanionDelegateAuthRequest::GetMaxConcurrency() const
{
    return 1; // Spec: max 1 concurrent CompanionDelegateAuthRequest
}

bool CompanionDelegateAuthRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    [[maybe_unused]] const std::optional<DeviceKey> &newPeerDevice,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new CompanionDelegateAuthRequest preempts existing one
    if (newRequestType == RequestType::COMPANION_DELEGATE_AUTH_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new CompanionDelegateAuth", GetDescription());
        return true;
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
