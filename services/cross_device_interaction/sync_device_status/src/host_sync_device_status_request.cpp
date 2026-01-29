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

#include "host_sync_device_status_request.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_manager.h"
#include "companion_sync_device_status_handler.h"
#include "error_guard.h"
#include "scope_guard.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "sync_device_status_message.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostSyncDeviceStatusRequest::HostSyncDeviceStatusRequest(int32_t hostUserId, const DeviceKey &companionDeviceKey,
    const std::string &companionDeviceName, SyncDeviceStatusCallback &&callback)
    : OutboundRequest(RequestType::HOST_SYNC_DEVICE_STATUS_REQUEST, 0, DEFAULT_REQUEST_TIMEOUT_MS),
      hostUserId_(hostUserId),
      companionDeviceKey_(companionDeviceKey),
      companionDeviceName_(companionDeviceName),
      callback_(std::move(callback))
{
    SetPeerDeviceKey(companionDeviceKey_);
}

void HostSyncDeviceStatusRequest::OnConnected()
{
    IAM_LOGI("%{public}s start", GetDescription());
    BeginCompanionCheck();
}

std::weak_ptr<OutboundRequest> HostSyncDeviceStatusRequest::GetWeakPtr()
{
    return weak_from_this();
}

void HostSyncDeviceStatusRequest::InvokeCallback(ResultCode result, const SyncDeviceStatus &syncDeviceStatus)
{
    ENSURE_OR_RETURN(callback_ != nullptr);
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [cb = std::move(callback_), result, status = syncDeviceStatus]() mutable {
            if (cb) {
                cb(result, status);
            }
        });
}

void HostSyncDeviceStatusRequest::CompleteWithError(ResultCode result)
{
    ENSURE_OR_RETURN(result != SUCCESS);
    InvokeCallback(result, {});

    IAM_LOGE("%{public}s complete with error result=%{public}d", GetDescription(), result);
    Destroy();
}

void HostSyncDeviceStatusRequest::CompleteWithSuccess(const SyncDeviceStatus &syncDeviceStatus)
{
    InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus);
    IAM_LOGI("%{public}s complete with success", GetDescription());
    Destroy();
}

void HostSyncDeviceStatusRequest::BeginCompanionCheck()
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    HostBeginCompanionCheckInput input { GetRequestId() };
    HostBeginCompanionCheckOutput output {};
    ResultCode ret = GetSecurityAgent().HostBeginCompanionCheck(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostBeginCompanionCheck failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([this]() {
        HostCancelCompanionCheckInput input = { GetRequestId() };
        ResultCode cancelRet = GetSecurityAgent().HostCancelCompanionCheck(input);
        if (cancelRet != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s HostCancelCompanionCheck failed ret=%{public}d", GetDescription(), cancelRet);
        }
    });

    if (!SendSyncDeviceStatusRequest(output.salt, output.challenge)) {
        IAM_LOGE("%{public}s SendSyncDeviceStatusRequest failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }

    errorGuard.Cancel();
}

bool HostSyncDeviceStatusRequest::SendSyncDeviceStatusRequest(const std::vector<uint8_t> &salt, uint64_t challenge)
{
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_VAL(localDeviceKey.has_value(), false);

    auto profile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    SyncDeviceStatusRequest syncDeviceStatusRequest = {};
    syncDeviceStatusRequest.protocolIdList = profile.protocols;
    syncDeviceStatusRequest.capabilityList = profile.capabilities;
    syncDeviceStatusRequest.hostDeviceKey.deviceUserId = hostUserId_;
    syncDeviceStatusRequest.salt = salt;
    syncDeviceStatusRequest.challenge = challenge;

    Attributes request = {};
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::SYNC_DEVICE_STATUS,
        request, [weakSelf = weak_from_this()](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleSyncDeviceStatusReply(message);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return false;
    }
    return true;
}

void HostSyncDeviceStatusRequest::HandleSyncDeviceStatusReply(const Attributes &reply)
{
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyDataOpt = DecodeSyncDeviceStatusReply(reply);
    ENSURE_OR_RETURN(replyDataOpt.has_value());
    const auto &replyData = *replyDataOpt;

    bool handleRet = EndCompanionCheck(replyData);
    ENSURE_OR_RETURN(handleRet);

    SyncDeviceStatus syncDeviceStatus = {};
    syncDeviceStatus.deviceKey = replyData.companionDeviceKey;
    syncDeviceStatus.protocolIdList = replyData.protocolIdList;
    syncDeviceStatus.capabilityList = replyData.capabilityList;
    syncDeviceStatus.secureProtocolId = replyData.secureProtocolId;
    syncDeviceStatus.deviceUserName = replyData.deviceUserName;

    if (cancelCompanionCheckGuard_ != nullptr) {
        cancelCompanionCheckGuard_->Cancel();
    }
    errorGuard.Cancel();
    CompleteWithSuccess(syncDeviceStatus);
}

bool HostSyncDeviceStatusRequest::EndCompanionCheck(const SyncDeviceStatusReply &reply)
{
    ENSURE_OR_RETURN_VAL(reply.result == ResultCode::SUCCESS, false);
    ENSURE_OR_RETURN_VAL(GetPeerDeviceKey().has_value(), false);

    auto companionStatus = GetCompanionManager().GetCompanionStatus(hostUserId_, companionDeviceKey_);
    if (!companionStatus) {
        IAM_LOGI("%{public}s companionStatus not exist", GetDescription());
        return true;
    }

    HostEndCompanionCheckInput input = {};
    input.requestId = GetRequestId();
    input.templateId = companionStatus->templateId;
    input.protocolVersionList = ProtocolIdConverter::ToUnderlyingVec(reply.protocolIdList);
    input.capabilityList = CapabilityConverter::ToUnderlyingVec(reply.capabilityList);
    input.secureProtocolId = reply.secureProtocolId;
    input.companionCheckResponse = reply.companionCheckResponse;
    ResultCode ret = GetSecurityAgent().HostEndCompanionCheck(input);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostEndCompanionCheck failed ret=%{public}d", GetDescription(), ret);
        GetCompanionManager().HandleCompanionCheckFail(companionStatus->templateId);
    } else {
        const auto &currentStatus = companionStatus->companionDeviceStatus;
        bool needUpdate =
            currentStatus.deviceUserName != reply.deviceUserName || currentStatus.deviceName != companionDeviceName_;
        if (needUpdate) {
            (void)GetCompanionManager().UpdateCompanionStatus(companionStatus->templateId, companionDeviceName_,
                reply.deviceUserName);
        }
    }
    return true;
}

bool HostSyncDeviceStatusRequest::NeedBeginCompanionCheck() const
{
    const auto &peerKey = GetPeerDeviceKey();
    if (!peerKey.has_value()) {
        return false;
    }

    auto allCompanionStatus = GetCompanionManager().GetAllCompanionStatus();
    for (const auto &companionStatus : allCompanionStatus) {
        const auto &deviceKey = companionStatus.companionDeviceStatus.deviceKey;
        if (deviceKey.idType == peerKey->idType && deviceKey.deviceId == peerKey->deviceId) {
            return true;
        }
    }
    return false;
}

uint32_t HostSyncDeviceStatusRequest::GetMaxConcurrency() const
{
    return 100; // Spec: max 100 concurrent HostSyncDeviceStatusRequest (TA limited to 10 by CA)
}

bool HostSyncDeviceStatusRequest::ShouldCancelOnNewRequest([[maybe_unused]] RequestType newRequestType,
    [[maybe_unused]] const std::optional<DeviceKey> &newPeerDevice,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: not preempted by any request type
    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
