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

#include "host_remove_host_binding_request.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_manager.h"
#include "companion_remove_host_binding_handler.h"
#include "error_guard.h"
#include "remove_host_binding_message.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostRemoveHostBindingRequest::HostRemoveHostBindingRequest(UserId hostUserId, TemplateId templateId,
    const DeviceKey &companionDeviceKey)
    : OutboundRequest(RequestType::HOST_REMOVE_HOST_BINDING_REQUEST, 0, DEFAULT_REQUEST_TIMEOUT_MS),
      hostUserId_(hostUserId),
      companionDeviceKey_(companionDeviceKey),
      templateId_(templateId)
{
}

bool HostRemoveHostBindingRequest::OnStart(ErrorGuard &errorGuard)
{
    IAM_LOGI("%{public}s", GetDescription());
    SetPeerDeviceKey(companionDeviceKey_);
    if (!OpenConnection()) {
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return false;
    }
    return true;
}

void HostRemoveHostBindingRequest::OnConnected()
{
    IAM_LOGI("%{public}s", GetDescription());
    SendRemoveHostBindingRequest();
}

void HostRemoveHostBindingRequest::SendRemoveHostBindingRequest()
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto peerDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN(peerDeviceKey.has_value());
    DeviceKey hostDeviceKey = {};
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    if (localDeviceKey.has_value()) {
        hostDeviceKey = *localDeviceKey;
    }
    hostDeviceKey.deviceUserId = hostUserId_;
    RemoveHostBindingRequest requestMsg = {
        .hostDeviceKey = hostDeviceKey,
        .companionUserId = peerDeviceKey->deviceUserId,
        .extraInfo = {},
    };
    Attributes request = {};
    bool encodeRet = EncodeRemoveHostBindingRequest(requestMsg, request);
    ENSURE_OR_RETURN(encodeRet);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::REMOVE_HOST_BINDING,
        request, [weakSelf = weak_from_this()](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleRemoveHostBindingReply(message);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

void HostRemoveHostBindingRequest::HandleRemoveHostBindingReply(const Attributes &message)
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyOpt = DecodeRemoveHostBindingReply(message);
    ENSURE_OR_RETURN(replyOpt.has_value());
    if (replyOpt->result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s remove host binding failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(replyOpt->result));
        errorGuard.UpdateErrorCode(replyOpt->result);
        return;
    }
    errorGuard.Cancel();
    CompleteWithSuccess();
}

std::weak_ptr<OutboundRequest> HostRemoveHostBindingRequest::GetWeakPtr()
{
    return shared_from_this();
}

void HostRemoveHostBindingRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s complete with error: %{public}d", GetDescription(), result);
    GetCompanionManager().HandleRemoveHostBindingComplete(templateId_);
    Destroy();
}

void HostRemoveHostBindingRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    GetCompanionManager().HandleRemoveHostBindingComplete(templateId_);
    Destroy();
}

uint32_t HostRemoveHostBindingRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent HostRemoveHostBindingRequest
}

bool HostRemoveHostBindingRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    [[maybe_unused]] const std::optional<DeviceKey> &newPeerDevice,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostRemoveHostBindingRequest preempts existing one
    if (newRequestType == RequestType::HOST_REMOVE_HOST_BINDING_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostRemoveHostBinding", GetDescription());
        return true;
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
