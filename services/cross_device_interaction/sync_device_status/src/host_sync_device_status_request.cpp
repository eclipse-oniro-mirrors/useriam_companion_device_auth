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

#include "adapter_manager.h"
#include "cda_scope_guard.h"
#include "common_message.h"
#include "companion_manager.h"
#include "companion_sync_device_status_handler.h"
#include "error_guard.h"
#include "iam_log_tracer.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "sync_device_status_message.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_SYNC_DEVICE_STATUS_REQUEST

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
    desc_.SetDeviceId(companionDeviceKey_);
    eventCollector_.SetHostUserId(hostUserId);
    eventCollector_.SetCompanionDeviceKey(companionDeviceKey);
    eventCollector_.SetConnectionName(GetConnectionName());
}

void HostSyncDeviceStatusRequest::OnConnected()
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    BeginCompanionCheck();
}

std::weak_ptr<OutboundRequest> HostSyncDeviceStatusRequest::GetWeakPtr()
{
    return weak_from_this();
}

void HostSyncDeviceStatusRequest::InvokeCallback(ResultCode result, const SyncDeviceStatus &syncDeviceStatus)
{
    if (callback_ == nullptr) {
        IAM_LOGI("%{public}s callback already sent", GetDescription());
        return;
    }
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [cb = std::move(callback_), result, status = syncDeviceStatus]() mutable {
            if (cb) {
                cb(result, status);
            }
        });
    callback_ = nullptr;
}

void HostSyncDeviceStatusRequest::CompleteWithError(ResultCode result)
{
    ENSURE_OR_RETURN_DESC(GetDescription(), result != SUCCESS);
    InvokeCallback(result, {});

    IAM_LOGE("%{public}s complete with error result=%{public}d", GetDescription(), result);
    eventCollector_.Report(result);
    Destroy();
}

void HostSyncDeviceStatusRequest::CompleteWithSuccess(const SyncDeviceStatus &syncDeviceStatus)
{
    InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus);
    IAM_LOGI("%{public}s complete with success", GetDescription());
    eventCollector_.Report(ResultCode::SUCCESS);
    Destroy();
}

void HostSyncDeviceStatusRequest::BeginCompanionCheck()
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    HostBeginCompanionCheckInput input { GetRequestId(), hostUserId_ };
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

void HostSyncDeviceStatusRequest::CollectSyncDeviceStatusEventInfo(const LocalDeviceProfile &profile)
{
    eventCollector_.SetProtocolIdList(ProtocolIdConverter::ToUnderlyingVec(profile.protocols));
    eventCollector_.SetCapabilityList(CapabilityConverter::ToUnderlyingVec(profile.capabilities));
}

SyncDeviceStatusRequest HostSyncDeviceStatusRequest::BuildSyncDeviceStatusRequest(const LocalDeviceProfile &profile,
    const std::vector<uint8_t> &salt, uint64_t challenge)
{
    SyncDeviceStatusRequest request = {};
    request.protocolIdList = profile.protocols;
    request.capabilityList = profile.capabilities;
    request.hostDeviceKey.deviceUserId = hostUserId_;
    request.salt = salt;
    request.challenge = challenge;
    return request;
}

HostEndCompanionCheckInput HostSyncDeviceStatusRequest::BuildHostEndCompanionCheckInput(TemplateId templateId,
    const SyncDeviceStatusReply &reply) const
{
    HostEndCompanionCheckInput input = {};
    input.requestId = GetRequestId();
    input.templateId = templateId;
    input.protocolVersionList = ProtocolIdConverter::ToUnderlyingVec(reply.protocolIdList);
    input.capabilityList = CapabilityConverter::ToUnderlyingVec(reply.capabilityList);
    input.secureProtocolId = reply.secureProtocolId;
    input.companionCheckResponse = reply.companionCheckResponse;
    return input;
}

bool HostSyncDeviceStatusRequest::SendSyncDeviceStatusRequest(const std::vector<uint8_t> &salt, uint64_t challenge)
{
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), localDeviceKey.has_value(), false);

    auto profile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    CollectSyncDeviceStatusEventInfo(profile);

    SyncDeviceStatusRequest request = BuildSyncDeviceStatusRequest(profile, salt, challenge);

    Attributes attrRequest = {};
    EncodeSyncDeviceStatusRequest(request, attrRequest);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::SYNC_DEVICE_STATUS,
        attrRequest, [weakSelf = weak_from_this()](const Attributes &message) {
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
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyDataOpt = DecodeSyncDeviceStatusReply(reply);
    ENSURE_OR_RETURN_DESC(GetDescription(), replyDataOpt.has_value());
    const auto &replyData = *replyDataOpt;

    bool handleRet = EndCompanionCheck(replyData);
    ENSURE_OR_RETURN_DESC(GetDescription(), handleRet);

    SyncDeviceStatus syncDeviceStatus = {};
    syncDeviceStatus.needSync = true;
    syncDeviceStatus.protocolIdList = replyData.protocolIdList;
    syncDeviceStatus.capabilityList = replyData.capabilityList;
    syncDeviceStatus.secureProtocolId = replyData.secureProtocolId;
    syncDeviceStatus.deviceUserName = replyData.deviceUserName;

    eventCollector_.SetSelectedProtocolIdList(ProtocolIdConverter::ToUnderlyingVec(syncDeviceStatus.protocolIdList));
    eventCollector_.SetSecureProtocolId(static_cast<uint16_t>(syncDeviceStatus.secureProtocolId));

    errorGuard.Cancel();
    CompleteWithSuccess(syncDeviceStatus);
}

bool HostSyncDeviceStatusRequest::EndCompanionCheck(const SyncDeviceStatusReply &reply)
{
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), reply.result == ResultCode::SUCCESS, false);
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), GetPeerDeviceKey().has_value(), false);

    auto companionStatus = QueryCompanionStatus();
    if (!companionStatus) {
        IAM_LOGI("%{public}s companionStatus not exist", GetDescription());
        return true;
    }

    eventCollector_.SetTemplateIdList({ companionStatus->templateId });
    desc_.SetTemplateId(companionStatus->templateId);

    ResultCode ret = CallHostEndCompanionCheck(companionStatus->templateId, reply);
    ProcessCompanionCheckResult(ret, *companionStatus, reply);

    if (cancelCompanionCheckGuard_ != nullptr) {
        cancelCompanionCheckGuard_->Cancel();
    }
    return true;
}

std::optional<CompanionStatus> HostSyncDeviceStatusRequest::QueryCompanionStatus()
{
    return GetCompanionManager().GetCompanionStatus(hostUserId_, companionDeviceKey_);
}

ResultCode HostSyncDeviceStatusRequest::CallHostEndCompanionCheck(TemplateId templateId,
    const SyncDeviceStatusReply &reply)
{
    HostEndCompanionCheckInput input = BuildHostEndCompanionCheckInput(templateId, reply);
    return GetSecurityAgent().HostEndCompanionCheck(input);
}

void HostSyncDeviceStatusRequest::ProcessCompanionCheckResult(ResultCode checkResult,
    const CompanionStatus &companionStatus, const SyncDeviceStatusReply &reply)
{
    if (checkResult != ResultCode::SUCCESS) {
        GetCompanionManager().SetTemplateInvalid(companionStatus.templateId, "companion check fail");
    }
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
