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

#include "companion_revoke_token_request.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "error_guard.h"
#include "host_revoke_token_handler.h"
#include "revoke_token_message.h"
#include "singleton_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionRevokeTokenRequest::CompanionRevokeTokenRequest(int32_t companionUserId, const DeviceKey &hostDeviceKey)
    : OutboundRequest(RequestType::COMPANION_REVOKE_TOKEN_REQUEST, 0, DEFAULT_REQUEST_TIMEOUT_MS),
      companionUserId_(companionUserId)
{
    SetPeerDeviceKey(hostDeviceKey);
}

void CompanionRevokeTokenRequest::OnConnected()
{
    IAM_LOGI("%{public}s", GetDescription());
    SendRevokeTokenRequest();
}

std::weak_ptr<OutboundRequest> CompanionRevokeTokenRequest::GetWeakPtr()
{
    return shared_from_this();
}

void CompanionRevokeTokenRequest::SendRevokeTokenRequest()
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto peerDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN(peerDeviceKey.has_value());
    DeviceKey companionDeviceKey = {};
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    if (localDeviceKey.has_value()) {
        companionDeviceKey = *localDeviceKey;
    }
    companionDeviceKey.deviceUserId = companionUserId_;
    RevokeTokenRequest requestMsg = { .hostUserId = peerDeviceKey->deviceUserId,
        .companionDeviceKey = companionDeviceKey };
    Attributes request = {};
    bool encodeRet = EncodeRevokeTokenRequest(requestMsg, request);
    ENSURE_OR_RETURN(encodeRet);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::COMPANION_REVOKE_TOKEN,
        request, [weakSelf = weak_from_this()](const Attributes &reply) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleRevokeTokenReply(reply);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

void CompanionRevokeTokenRequest::HandleRevokeTokenReply(const Attributes &message)
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyOpt = DecodeRevokeTokenReply(message);
    ENSURE_OR_RETURN(replyOpt.has_value());
    const auto &reply = *replyOpt;
    if (reply.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s revoke token failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(reply.result));
        errorGuard.UpdateErrorCode(reply.result);
        return;
    }
    errorGuard.Cancel();
    CompleteWithSuccess();
}

void CompanionRevokeTokenRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s: revoke token request failed, result=%{public}d", GetDescription(), result);
    Destroy();
}

void CompanionRevokeTokenRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    Destroy();
}

uint32_t CompanionRevokeTokenRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent CompanionRevokeTokenRequest
}

bool CompanionRevokeTokenRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    [[maybe_unused]] const std::optional<DeviceKey> &newPeerDevice,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new CompanionRevokeTokenRequest preempts existing one
    if (newRequestType == RequestType::COMPANION_REVOKE_TOKEN_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new CompanionRevokeToken", GetDescription());
        return true;
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
