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

#include "companion_request_resync_request.h"

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "error_guard.h"
#include "resync_device_status_message.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_COMPANION_REQUEST_RESYNC_REQUEST

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr uint32_t MAX_RESYNC_CONCURRENCY = 10;
}

CompanionRequestResyncRequest::CompanionRequestResyncRequest(const DeviceKey &hostDeviceKey,
    ResultCodeCallback onComplete)
    : OutboundRequest(RequestType::COMPANION_REQUEST_RESYNC_REQUEST, 0, DEFAULT_REQUEST_TIMEOUT_MS),
      onComplete_(std::move(onComplete))
{
    SetPeerDeviceKey(hostDeviceKey);
    desc_.SetDeviceId(hostDeviceKey);
}

void CompanionRequestResyncRequest::OnConnected()
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    SendRequestDeviceResyncRequest();
}

std::weak_ptr<OutboundRequest> CompanionRequestResyncRequest::GetWeakPtr()
{
    return weak_from_this();
}

void CompanionRequestResyncRequest::SendRequestDeviceResyncRequest()
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto peerDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN_DESC(GetDescription(), peerDeviceKey.has_value());
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_DESC(GetDescription(), localDeviceKey.has_value());

    DeviceKey companionDeviceKey = localDeviceKey.value();
    RequestDeviceResyncRequest requestMsg = { .companionDeviceKey = companionDeviceKey };
    Attributes request = {};
    EncodeRequestDeviceResyncRequest(requestMsg, request);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::REQUEST_DEVICE_RESYNC,
        request, [weakSelf = weak_from_this()](const Attributes &reply) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleRequestDeviceResyncReply(reply);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

void CompanionRequestResyncRequest::HandleRequestDeviceResyncReply(const Attributes &message)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyOpt = DecodeRequestDeviceResyncReply(message);
    ENSURE_OR_RETURN_DESC(GetDescription(), replyOpt.has_value());
    if (replyOpt->result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s request resync failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(replyOpt->result));
        errorGuard.UpdateErrorCode(replyOpt->result);
        return;
    }
    errorGuard.Cancel();
    CompleteWithSuccess();
}

void CompanionRequestResyncRequest::CompleteWithError(ResultCode result)
{
    if (!AcquireCompletion()) {
        return;
    }
    IAM_LOGI("%{public}s: request resync failed, result=%{public}d", GetDescription(), result);
    if (onComplete_) {
        onComplete_(result);
        onComplete_ = nullptr;
    }
    Destroy();
}

void CompanionRequestResyncRequest::CompleteWithSuccess()
{
    if (!AcquireCompletion()) {
        return;
    }
    IAM_LOGI("%{public}s complete with success", GetDescription());
    if (onComplete_) {
        onComplete_(ResultCode::SUCCESS);
        onComplete_ = nullptr;
    }
    Destroy();
}

uint32_t CompanionRequestResyncRequest::GetMaxConcurrency() const
{
    return MAX_RESYNC_CONCURRENCY;
}

bool CompanionRequestResyncRequest::ShouldCancelOnNewRequest(const IRequest &newRequest,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    if (newRequest.GetRequestType() != RequestType::COMPANION_REQUEST_RESYNC_REQUEST) {
        return false;
    }

    auto myPeer = GetPeerDeviceKey();
    auto newPeer = newRequest.GetPeerDeviceKey();
    // Compare by physical device only (idType + deviceId), ignoring deviceUserId: a resync targets the
    // same physical host regardless of which user is recorded on it.
    if (myPeer.has_value() && newPeer.has_value() &&
        (myPeer->idType != newPeer->idType || myPeer->deviceId != newPeer->deviceId)) {
        return false;
    }
    IAM_LOGI("%{public}s: preempted by new CompanionRequestResync for same host", GetDescription());
    return true;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
