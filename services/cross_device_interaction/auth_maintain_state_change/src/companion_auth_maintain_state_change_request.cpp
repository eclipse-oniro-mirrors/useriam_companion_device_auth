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

#include "companion_auth_maintain_state_change_request.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "auth_maintain_state_change_message.h"
#include "error_guard.h"
#include "host_auth_maintain_state_change_handler.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionAuthMaintainStateChangeRequest::CompanionAuthMaintainStateChangeRequest(const DeviceKey &hostDeviceKey,
    bool authMaintainState)
    : OutboundRequest(RequestType::COMPANION_AUTH_MAINTAIN_STATE_CHANGE_REQUEST, 0, DEFAULT_REQUEST_TIMEOUT_MS),
      authMaintainState_(authMaintainState),
      hostDeviceKey_(hostDeviceKey)
{
    SetPeerDeviceKey(hostDeviceKey_);
}

std::weak_ptr<OutboundRequest> CompanionAuthMaintainStateChangeRequest::GetWeakPtr()
{
    return shared_from_this();
}

void CompanionAuthMaintainStateChangeRequest::OnConnected()
{
    IAM_LOGI("%{public}s start", GetDescription());
    SendAuthMaintainStateChangeRequest();
}

void CompanionAuthMaintainStateChangeRequest::SendAuthMaintainStateChangeRequest()
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    AuthMaintainStateChangeRequestMsg requestMsg = { .authMaintainState = authMaintainState_ };
    Attributes request = {};
    bool encodeRet = EncodeAuthMaintainStateChangeRequest(requestMsg, request);
    ENSURE_OR_RETURN(encodeRet);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::AUTH_MAINTAIN_STATE_CHANGE,
        request, [weakSelf = weak_from_this()](const Attributes &reply) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleAuthMaintainStateChangeReply(reply);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

void CompanionAuthMaintainStateChangeRequest::HandleAuthMaintainStateChangeReply(const Attributes &message)
{
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyOpt = DecodeAuthMaintainStateChangeReply(message);
    ENSURE_OR_RETURN(replyOpt.has_value());
    if (replyOpt->result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s auth maintain state change failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(replyOpt->result));
        errorGuard.UpdateErrorCode(replyOpt->result);
        return;
    }
    errorGuard.Cancel();
    CompleteWithSuccess();
}

void CompanionAuthMaintainStateChangeRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s complete with error: %{public}d", GetDescription(), result);
    Destroy();
}

void CompanionAuthMaintainStateChangeRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    Destroy();
}

uint32_t CompanionAuthMaintainStateChangeRequest::GetMaxConcurrency() const
{
    return 1;
}

bool CompanionAuthMaintainStateChangeRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    const std::optional<DeviceKey> &newPeerDevice, uint32_t subsequentSameTypeCount) const
{
    (void)newRequestType;
    (void)newPeerDevice;
    (void)subsequentSameTypeCount;
    return false;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
