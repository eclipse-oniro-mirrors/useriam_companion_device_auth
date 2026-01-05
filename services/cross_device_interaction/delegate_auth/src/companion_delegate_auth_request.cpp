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

#include "ipc_skeleton.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "common_message.h"
#include "companion_delegate_auth_callback.h"
#include "cross_device_comm_manager_impl.h"
#include "delegate_auth_message.h"
#include "error_guard.h"
#include "host_binding_manager.h"
#include "security_agent.h"
#include "service_converter.h"
#include "singleton_manager.h"
#include "token_setproc.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

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
    IAM_LOGI("%{public}s", GetDescription());

    hostDeviceKey_ = PeerDeviceKey();

    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_VAL(localDeviceKey.has_value(), false);
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
    IAM_LOGI("%{public}s", GetDescription());
    uint64_t challenge = 0;
    Atl atl = 0;
    bool ret = SecureAgentBeginDelegateAuth(challenge, atl);
    ENSURE_OR_RETURN_VAL(ret, false);

    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_VAL(localDeviceKey.has_value(), false);

    UserAuth::WidgetAuthParam authParam = {};
    authParam.userId = localDeviceKey->deviceUserId;
    authParam.challenge = ConvertUint64ToUint8Vec(challenge);
    authParam.authTypes = { UserAuth::AuthType::PIN, UserAuth::AuthType::FACE, UserAuth::AuthType::FINGERPRINT };
    authParam.authTrustLevel = static_cast<UserAuth::AuthTrustLevel>(atl);
    authParam.reuseUnlockResult.isReuse = false;

    UserAuth::WidgetParam widgetParam = {};
    widgetParam.title = "Delegate Authentication";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = UserAuth::WindowModeType::UNKNOWN_WINDOW_MODE;

    auto weakSelf = std::weak_ptr<CompanionDelegateAuthRequest>(shared_from_this());
    std::shared_ptr<UserAuth::AuthenticationCallback> callback = std::make_shared<CompanionDelegateAuthCallback>(
        [weakSelf](ResultCode result, const std::vector<uint8_t> &extraInfo) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleDelegateAuthResult(result, extraInfo);
        });

    auto callerTokenId = IPCSkeleton::GetCallingTokenID();
    SetFirstCallerTokenID(callerTokenId);
    uint64_t contextId = GetUserAuthAdapter().BeginWidgetAuth(authParam, widgetParam, callback);
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

void CompanionDelegateAuthRequest::HandleDelegateAuthResult(ResultCode resultCode,
    const std::vector<uint8_t> &extraInfo)
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    IAM_LOGI("%{public}s", GetDescription());
    contextId_.reset();

    Attributes message(extraInfo);
    std::vector<uint8_t> authToken;
    bool getAuthToken = message.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authToken);
    ENSURE_OR_RETURN(getAuthToken);

    std::vector<uint8_t> delegateAuthResult;
    bool result = SecurityAgentEndDelegateAuth(resultCode, authToken, delegateAuthResult);
    if (!result) {
        IAM_LOGE("%{public}s SecurityAgentEndDelegateAuth failed", GetDescription());
        return;
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
    IAM_LOGI("%{public}s", GetDescription());
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
