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

#include "outbound_request.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "relative_timer.h"
#include "request_aborted_message.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
OutboundRequest::OutboundRequest(RequestType requestType, ScheduleId scheduleId, uint32_t timeoutMs)
    : BaseRequest(requestType, scheduleId, timeoutMs)
{
}

void OutboundRequest::Start()
{
    IAM_LOGI("%{public}s start", GetDescription());

    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    bool onStartRet = OnStart(errorGuard);
    ENSURE_OR_RETURN(onStartRet);

    errorGuard.Cancel();
    IAM_LOGI("%{public}s started successfully", GetDescription());
}

bool OutboundRequest::OnStart(ErrorGuard &errorGuard)
{
    if (!OpenConnection()) {
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return false;
    }
    return true;
}

bool OutboundRequest::Cancel(ResultCode resultCode)
{
    if (cancelled_) {
        IAM_LOGI("%{public}s already cancelled, skip", GetDescription());
        return true;
    }
    cancelled_ = true;
    IAM_LOGI("%{public}s cancel", GetDescription());

    bool onCancelRet = OnCancel();
    if (!onCancelRet) {
        IAM_LOGE("%{public}s cancel failed", GetDescription());
    }

    CompleteWithError(resultCode);
    return onCancelRet;
}

bool OutboundRequest::OnCancel()
{
    return true;
}

void OutboundRequest::Destroy()
{
    CloseConnection();
    BaseRequest::Destroy();
}

void OutboundRequest::SetPeerDeviceKey(const DeviceKey &peerDeviceKey)
{
    peerDeviceKey_ = peerDeviceKey;
}

std::optional<DeviceKey> OutboundRequest::GetPeerDeviceKey() const
{
    return peerDeviceKey_;
}

const std::string &OutboundRequest::GetConnectionName() const
{
    return connectionName_;
}

bool OutboundRequest::OpenConnection()
{
    IAM_LOGI("%{public}s open connection", GetDescription());

    ENSURE_OR_RETURN_VAL(peerDeviceKey_.has_value(), false);

    connectionStatusSubscription_ = GetCrossDeviceCommManager().SubscribeConnectionStatus(connectionName_,
        [weakSelf = GetWeakPtr()](const std::string &connName, ConnectionStatus status, const std::string &reason) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            if (self->connectionName_.empty()) {
                return;
            }
            ENSURE_OR_RETURN(self->connectionName_ == connName);

            self->HandleConnectionStatus(connName, status, reason);
        });
    ENSURE_OR_RETURN_VAL(connectionStatusSubscription_ != nullptr, false);

    requestAbortedSubscription_ =
        GetCrossDeviceCommManager().SubscribeMessage(connectionName_, MessageType::REQUEST_ABORTED,
            [weakSelf = GetWeakPtr()](const Attributes &request, std::function<void(const Attributes &)> onReply) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleRequestAborted(request, onReply);
            });
    ENSURE_OR_RETURN_VAL(requestAbortedSubscription_ != nullptr, false);

    if (!GetCrossDeviceCommManager().OpenConnection(*peerDeviceKey_, connectionName_)) {
        IAM_LOGE("%{public}s OpenConnection failed", GetDescription());
        return false;
    }

    IAM_LOGI("%{public}s open connection %{public}s success", GetDescription(), connectionName_.c_str());
    return true;
}

void OutboundRequest::CloseConnection()
{
    if (connectionName_.empty()) {
        IAM_LOGI("%{public}s connection is already closed", GetDescription());
        return;
    }

    IAM_LOGI("%{public}s closing connection %{public}s", GetDescription(), connectionName_.c_str());
    GetCrossDeviceCommManager().CloseConnection(connectionName_);
    connectionName_.clear();
}

void OutboundRequest::HandleConnectionStatus(const std::string &connName, ConnectionStatus status,
    const std::string &reason)
{
    IAM_LOGI("%{public}s connection status changed: %{public}s, status: %{public}d, reason: %{public}s",
        GetDescription(), connName.c_str(), static_cast<int32_t>(status), reason.c_str());

    switch (status) {
        case ConnectionStatus::ESTABLISHING:
            break;
        case ConnectionStatus::CONNECTED:
            OnConnected();
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

void OutboundRequest::HandleRequestAborted(const Attributes &request,
    [[maybe_unused]] std::function<void(const Attributes &)> onReply)
{
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });
    RequestAbortedRequest abortReq;
    bool decodeRet = DecodeRequestAbortedRequest(request, abortReq);
    ENSURE_OR_RETURN(decodeRet);

    IAM_LOGI("%{public}s received RequestAborted: result=%{public}d, reason=%{public}s", GetDescription(),
        static_cast<int32_t>(abortReq.result), abortReq.reason.c_str());

    errorGuard.UpdateErrorCode(ResultCode::SUCCESS);
    CompleteWithError(abortReq.result);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
