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

#include "inbound_request.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "error_guard.h"
#include "request_aborted_message.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
InboundRequest::InboundRequest(RequestType requestType, const std::string &connectionName,
    const DeviceKey &peerDeviceKey)
    : BaseRequest(requestType),
      connectionName_(connectionName),
      peerDeviceKey_(peerDeviceKey)
{
}

void InboundRequest::Start()
{
    IAM_LOGI("%{public}s start", GetDescription());

    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    ENSURE_OR_RETURN(!connectionName_.empty());
    connectionStatusSubscription_ = GetCrossDeviceCommManager().SubscribeConnectionStatus(connectionName_,
        [weakSelf = GetWeakPtr()](const std::string &connName, ConnectionStatus status, const std::string &reason) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            ENSURE_OR_RETURN(self->connectionName_ == connName);

            self->HandleConnectionStatus(connName, status, reason);
        });
    ENSURE_OR_RETURN(connectionStatusSubscription_ != nullptr);

    ConnectionStatus status = GetCrossDeviceCommManager().GetConnectionStatus(connectionName_);
    ENSURE_OR_RETURN(status == ConnectionStatus::CONNECTED);

    bool ret = OnStart(errorGuard);
    if (!ret) {
        IAM_LOGE("%{public}s OnStart failed", GetDescription());
        return;
    }

    errorGuard.Cancel();
    IAM_LOGI("%{public}s started successfully", GetDescription());
}

bool InboundRequest::Cancel(ResultCode resultCode)
{
    if (cancelled_) {
        IAM_LOGI("%{public}s already cancelled, skip", GetDescription());
        return true;
    }
    cancelled_ = true;
    IAM_LOGI("%{public}s cancel", GetDescription());
    SendRequestAborted(resultCode, "request cancelled");
    CompleteWithError(resultCode);
    return true;
}

std::optional<DeviceKey> InboundRequest::GetPeerDeviceKey() const
{
    return peerDeviceKey_;
}

const DeviceKey &InboundRequest::PeerDeviceKey() const
{
    return peerDeviceKey_.value();
}

const std::string &InboundRequest::GetConnectionName() const
{
    return connectionName_;
}

void InboundRequest::HandleConnectionStatus(const std::string &connName, ConnectionStatus status,
    const std::string &reason)
{
    IAM_LOGI("%{public}s connection status changed: %{public}s, status: %{public}d, reason: %{public}s",
        GetDescription(), connName.c_str(), static_cast<int32_t>(status), reason.c_str());

    switch (status) {
        case ConnectionStatus::ESTABLISHING:
            break;
        case ConnectionStatus::CONNECTED:
            break;
        case ConnectionStatus::DISCONNECTED:
            IAM_LOGI("%{public}s disconnected", GetDescription());
            CompleteWithError(ResultCode::COMMUNICATION_ERROR);
            break;
        default:
            IAM_LOGE("%{public}s unknown connection status: %{public}d", GetDescription(),
                static_cast<int32_t>(status));
    }
}

void InboundRequest::SendRequestAborted(ResultCode result, const std::string &reason)
{
    IAM_LOGI("%{public}s sending RequestAborted: result=%{public}d, reason=%{public}s", GetDescription(),
        static_cast<int32_t>(result), reason.c_str());

    RequestAbortedRequest abortReq;
    abortReq.result = result;
    abortReq.reason = reason;

    Attributes request;
    bool encodeRet = EncodeRequestAbortedRequest(abortReq, request);
    ENSURE_OR_RETURN(encodeRet);

    GetCrossDeviceCommManager().SendMessage(connectionName_, MessageType::REQUEST_ABORTED, request,
        [description = GetDescription()](const Attributes &reply) {
            IAM_LOGI("%{public}s RequestAborted reply received", description);
            (void)reply;
        });
}

void InboundRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGE("%{public}s completing with error result=%{public}d", GetDescription(), static_cast<int32_t>(result));
    Destroy();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
