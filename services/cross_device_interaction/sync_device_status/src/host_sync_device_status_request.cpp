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
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "cda_scope_guard.h"
#include "common_message.h"
#include "companion_manager.h"
#include "companion_sync_device_status_handler.h"
#include "error_guard.h"
#include "request_stages.h"
#include "security_agent.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "sync_device_status_message.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_SYNC_DEVICE_STATUS_REQUEST

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostSyncDeviceStatusRequest::HostSyncDeviceStatusRequest(const UserKey &hostUserKey,
    const DeviceKey &companionDeviceKey, ConnectionMode connectionMode, SyncTriggerReason triggerReason,
    SyncDeviceStatusCallback &&callback)
    : OutboundRequest(RequestType::HOST_SYNC_DEVICE_STATUS_REQUEST, connectionMode, 0, DEFAULT_REQUEST_TIMEOUT_MS),
      hostUserKey_(hostUserKey),
      companionDeviceKey_(companionDeviceKey),
      callback_(std::move(callback))
{
    SetPeerDeviceKey(companionDeviceKey_);
    desc_.SetDeviceId(companionDeviceKey_);
    eventCollector_.SetHostUserKey(hostUserKey_);
    eventCollector_.SetCompanionDeviceKey(companionDeviceKey);
    eventCollector_.SetTriggerReason("syncTriggerReason " + std::to_string(static_cast<int32_t>(triggerReason)));
}

void HostSyncDeviceStatusRequest::OnConnected()
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    eventCollector_.SetConnectionName(GetConnectionName());
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
    if (!AcquireCompletion()) {
        return;
    }
    cancelCompanionCheckGuard_.reset();
    InvokeCallback(result, {});
    IAM_LOGE("%{public}s complete with error result=%{public}d", GetDescription(), result);
    eventCollector_.Report(result);
    Destroy();
}

void HostSyncDeviceStatusRequest::CompleteWithSuccess(const SyncDeviceStatus &syncDeviceStatus)
{
    if (!AcquireCompletion()) {
        return;
    }
    cancelCompanionCheckGuard_.reset();
    InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus);
    IAM_LOGI("%{public}s complete with success", GetDescription());
    eventCollector_.Report(ResultCode::SUCCESS);
    Destroy();
}

void HostSyncDeviceStatusRequest::BeginCompanionCheck()
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    HostBeginCompanionCheckInput input { GetRequestId(), hostUserKey_.userId };
    HostBeginCompanionCheckOutput output {};
    ResultCode ret = GetSecurityAgent().HostBeginCompanionCheck(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostBeginCompanionCheck failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    cancelCompanionCheckGuard_ =
        std::make_unique<ScopeGuard>([requestId = GetRequestId(), desc = std::string(GetDescription())]() {
            HostCancelCompanionCheckInput input = { requestId };
            ResultCode cancelRet = GetSecurityAgent().HostCancelCompanionCheck(input);
            if (cancelRet != ResultCode::SUCCESS) {
                IAM_LOGE("%{public}s HostCancelCompanionCheck failed ret=%{public}d", desc.c_str(), cancelRet);
            }
        });
    ENSURE_OR_RETURN(cancelCompanionCheckGuard_ != nullptr);

    if (!SendSyncDeviceStatusRequest(output.salt, output.challenge)) {
        IAM_LOGE("%{public}s SendSyncDeviceStatusRequest failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }

    errorGuard.Cancel();
}

void HostSyncDeviceStatusRequest::CollectSyncDeviceStatusEventInfo(const LocalDeviceProfile &localProfile)
{
    eventCollector_.SetProtocolIdList(ProtocolIdConverter::ToUnderlyingVec(localProfile.protocols));
    eventCollector_.SetCapabilityList(CapabilityConverter::ToUnderlyingVec(localProfile.hostCapabilities));
}

SyncDeviceStatusRequest HostSyncDeviceStatusRequest::BuildSyncDeviceStatusRequest(
    const LocalDeviceProfile &localProfile, const std::vector<uint8_t> &salt, uint64_t challenge)
{
    SyncDeviceStatusRequest request = {};
    request.hostProtocolIdList = localProfile.protocols;
    request.hostCapabilityList = localProfile.hostCapabilities;
    request.hostDeviceKey.deviceUserId = hostUserKey_.userId;
    request.hostDeviceKey.deviceSubProfileId = hostUserKey_.subProfileId;
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
    input.secureProtocolId = reply.secureProtocolId;
    input.companionCheckResponse = reply.companionCheckResponse;
    return input;
}

bool HostSyncDeviceStatusRequest::SendSyncDeviceStatusRequest(const std::vector<uint8_t> &salt, uint64_t challenge)
{
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), localDeviceKey.has_value(), false);

    auto localProfile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    CollectSyncDeviceStatusEventInfo(localProfile);

    SyncDeviceStatusRequest request = BuildSyncDeviceStatusRequest(localProfile, salt, challenge);
    hostProtocolIdList_ = request.hostProtocolIdList;

    Attributes attrRequest = {};
    EncodeSyncDeviceStatusRequest(request, attrRequest);
    eventCollector_.EnterWait(HostSyncDeviceStatusStages::WAIT_SYNC_DEVICE_STATUS_REPLY);

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
    eventCollector_.ExitWait(HostSyncDeviceStatusStages::DONE_SYNC_DEVICE_STATUS_REPLY);
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    if (IsFinished()) {
        IAM_LOGI("%{public}s already cancelled/completed, drop late sync device status", GetDescription());
        return;
    }
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyDataOpt = DecodeSyncDeviceStatusReply(reply);
    ENSURE_OR_RETURN_DESC(GetDescription(), replyDataOpt.has_value());
    const auto &replyData = *replyDataOpt;

    if (replyData.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s peer sync failed, peerResult=%{public}d", GetDescription(),
            static_cast<int32_t>(replyData.result));
        ResultCode reportCode = (replyData.result == ResultCode::PROTOCOL_NEGOTIATION_FAILED ||
                                    replyData.result == ResultCode::SECURE_PROTOCOL_NOT_SUPPORTED ||
                                    replyData.result == ResultCode::NOT_ENROLLED)
            ? replyData.result
            : ResultCode::PEER_SYNC_FAILED;
        errorGuard.UpdateErrorCode(reportCode);
        return;
    }

    auto companionStatus = QueryCompanionStatus(replyData);
    bool hasProof = !replyData.companionCheckResponse.empty();
    if (ResultCode validationRet = ValidateReplyParameters(replyData); validationRet != ResultCode::SUCCESS) {
        errorGuard.UpdateErrorCode(validationRet);
        return;
    }
    std::vector<Capability> authenticatedCapabilities;
    EndCompanionCheck(replyData, companionStatus, authenticatedCapabilities);
    UpdateCompanionUserIdAndSubProfileId(
        UserKey { replyData.companionDeviceKey.deviceUserId, replyData.companionDeviceKey.deviceSubProfileId });

    SyncDeviceStatus syncDeviceStatus = BuildSyncDeviceStatus(replyData, hasProof, authenticatedCapabilities);

    eventCollector_.SetPeerProtocolIdList(
        ProtocolIdConverter::ToUnderlyingVec(syncDeviceStatus.companionProtocolIdList));
    if (companionStatus.has_value() && companionStatus->enrolledProtocolId != ProtocolId::INVALID) {
        eventCollector_.SetSelectedProtocolId(ProtocolIdConverter::ToUnderlying(companionStatus->enrolledProtocolId));
    }
    eventCollector_.SetSecureProtocolId(static_cast<uint16_t>(syncDeviceStatus.secureProtocolId));

    errorGuard.Cancel();
    CompleteWithSuccess(syncDeviceStatus);
}

SyncDeviceStatus HostSyncDeviceStatusRequest::BuildSyncDeviceStatus(const SyncDeviceStatusReply &reply, bool hasProof,
    const std::vector<Capability> &authenticatedCapabilities) const
{
    SyncDeviceStatus syncDeviceStatus = {};
    syncDeviceStatus.needSync = true;
    syncDeviceStatus.companionProtocolIdList = reply.companionProtocolIdList;
    syncDeviceStatus.companionCapabilityList = hasProof ? authenticatedCapabilities : reply.companionCapabilityList;
    syncDeviceStatus.businessIdList = reply.businessIdList;
    syncDeviceStatus.secureProtocolId = reply.secureProtocolId;
    syncDeviceStatus.deviceUserName = reply.deviceUserName;
    syncDeviceStatus.deviceName = reply.deviceName;
    syncDeviceStatus.deviceUserKey =
        UserKey { reply.companionDeviceKey.deviceUserId, reply.companionDeviceKey.deviceSubProfileId };
    syncDeviceStatus.deviceSubProfileName = reply.deviceSubProfileName;
    return syncDeviceStatus;
}

std::optional<CompanionStatus> HostSyncDeviceStatusRequest::QueryCompanionStatus(
    const SyncDeviceStatusReply &reply) const
{
    DeviceKey peerKey = companionDeviceKey_;
    peerKey.deviceUserId = reply.companionDeviceKey.deviceUserId;
    peerKey.deviceSubProfileId = reply.companionDeviceKey.deviceSubProfileId;
    return GetCompanionManager().GetCompanionStatus(hostUserKey_, peerKey);
}

ResultCode HostSyncDeviceStatusRequest::ValidateReplyParameters(const SyncDeviceStatusReply &reply) const
{
    if (reply.companionProtocolIdList.empty()) {
        return ResultCode::PROTOCOL_NEGOTIATION_FAILED;
    }
    if (IntersectLists(reply.companionProtocolIdList, hostProtocolIdList_).empty()) {
        return ResultCode::PROTOCOL_NEGOTIATION_FAILED;
    }
    return ResultCode::SUCCESS;
}

void HostSyncDeviceStatusRequest::EndCompanionCheck(const SyncDeviceStatusReply &reply,
    const std::optional<CompanionStatus> &companionStatus, std::vector<Capability> &outCapabilities)
{
    if (!companionStatus) {
        IAM_LOGI("%{public}s companionStatus not exist", GetDescription());
        return;
    }

    eventCollector_.SetTemplateIdList({ companionStatus->templateId });
    desc_.SetTemplateId(companionStatus->templateId);

    if (reply.companionCheckResponse.empty()) {
        IAM_LOGW("%{public}s bound peer returned no proof; binding loss or legacy peer check failure",
            GetDescription());
        return;
    }

    HostEndCompanionCheckOutput checkOutput = {};
    ResultCode ret = HostEndCompanionCheck(companionStatus->templateId, reply, checkOutput);
    if (cancelCompanionCheckGuard_ != nullptr) {
        cancelCompanionCheckGuard_->Cancel();
    }
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s authenticated companion check failed ret=%{public}d", GetDescription(),
            static_cast<int32_t>(ret));
        std::string reason = "sync companion check failed";
        if (ret == ResultCode::CAPABILITY_NEGOTIATION_FAILED) {
            reason = "sync capability list diverged";
        } else if (ret == ResultCode::PROTOCOL_NEGOTIATION_FAILED) {
            reason = "sync protocol list diverged";
        }
        GetCompanionManager().SetTemplateInvalid(companionStatus->templateId, reason);
        // Companion check failure only invalidates the credential; the sync round still succeeds.
        return;
    }
    outCapabilities = CapabilityConverter::FromUnderlyingVec(checkOutput.companionCapabilityList);
}

ResultCode HostSyncDeviceStatusRequest::HostEndCompanionCheck(TemplateId templateId, const SyncDeviceStatusReply &reply,
    HostEndCompanionCheckOutput &output)
{
    HostEndCompanionCheckInput input = BuildHostEndCompanionCheckInput(templateId, reply);
    return GetSecurityAgent().HostEndCompanionCheck(input, output);
}

uint32_t HostSyncDeviceStatusRequest::GetMaxConcurrency() const
{
    return 100; // Spec: max 100 concurrent HostSyncDeviceStatusRequest (TA limited to 10 by CA)
}

bool HostSyncDeviceStatusRequest::ShouldCancelOnNewRequest([[maybe_unused]] const IRequest &newRequest,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: not preempted by any request type
    return false;
}

void HostSyncDeviceStatusRequest::UpdateCompanionUserIdAndSubProfileId(const UserKey &companionUserKey)
{
    IAM_LOGI("companionUserId: %{public}d, companionSubProfileId: %{public}d", companionUserKey.userId,
        companionUserKey.subProfileId);
    companionDeviceKey_.deviceUserId = companionUserKey.userId;
    companionDeviceKey_.deviceSubProfileId = companionUserKey.subProfileId;
    SetPeerDeviceKey(companionDeviceKey_);
    desc_.SetDeviceId(companionDeviceKey_);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
