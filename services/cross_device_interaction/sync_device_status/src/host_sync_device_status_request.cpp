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
#include "iam_para2str.h"

#include "adapter_manager.h"
#include "binding_signature_message.h"
#include "cda_scope_guard.h"
#include "common_message.h"
#include "companion_manager.h"
#include "companion_sync_device_status_handler.h"
#include "cross_device_common.h"
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

    cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>(
        [requestId = GetRequestId()]() { GetSecurityAgent().HostCancelCompanionCheck({ requestId }); });
    ENSURE_OR_RETURN(cancelCompanionCheckGuard_ != nullptr);

    auto syncRequest = ComposeSyncDeviceStatusRequest(output.salt, output.challenge);
    ENSURE_OR_RETURN_DESC(GetDescription(), syncRequest != nullptr);

    if (GetCompanionManager().FilterCompanionStatus(hostUserKey_, companionDeviceKey_.AsPhysical()).empty()) {
        IAM_LOGI("%{public}s no credentials, unprotected discovery sync", GetDescription());
        SendSyncDeviceStatusRequest(syncRequest, std::nullopt);
        errorGuard.Cancel();
        return;
    }

    // clang-format off
    if (GetCompanionManager()
        .FilterCompanionStatus(hostUserKey_, companionDeviceKey_.AsPhysical(), ProtocolId::VERSION_2)
        .empty()) {
        // clang-format on
        // V1-only: nothing to sign, and the legacy companion TA rejects any list containing V2
        IAM_LOGI("%{public}s v1-only credentials, unprotected v1 sync without challenge round", GetDescription());
        SendSyncDeviceStatusRequest(syncRequest, ProtocolId::VERSION_1);
        errorGuard.Cancel();
        return;
    }

    RequestBindingSignatureChallenge(GetConnectionName(), hostUserKey_, std::nullopt,
        [weakSelf = weak_from_this(), syncRequest](ResultCode resultCode,
            const BindingSignatureChallengeResult &challengeResult) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleBindingSignatureChallengeResult(resultCode, challengeResult, syncRequest);
        });

    errorGuard.Cancel();
}

std::shared_ptr<Attributes> HostSyncDeviceStatusRequest::ComposeSyncDeviceStatusRequest(
    const std::vector<uint8_t> &salt, uint64_t challenge)
{
    auto localProfile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    SyncDeviceStatusRequest request = BuildSyncDeviceStatusRequest(localProfile, salt, challenge);
    eventCollector_.SetCapabilityList(CapabilityConverter::ToUnderlyingVec(request.hostCapabilityList));

    auto syncRequest = std::make_shared<Attributes>();
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), syncRequest != nullptr, nullptr);
    EncodeSyncDeviceStatusRequest(request, *syncRequest);
    return syncRequest;
}

SyncDeviceStatusRequest HostSyncDeviceStatusRequest::BuildSyncDeviceStatusRequest(
    const LocalDeviceProfile &localProfile, const std::vector<uint8_t> &salt, uint64_t challenge)
{
    SyncDeviceStatusRequest request = {};
    request.hostProtocolIdList = localProfile.hostProtocols;
    request.hostCapabilityList = localProfile.hostCapabilities;
    request.hostDeviceKey.deviceUserId = hostUserKey_.userId;
    request.hostDeviceKey.deviceSubProfileId = hostUserKey_.subProfileId;
    request.salt = salt;
    request.challenge = challenge;
    return request;
}

void HostSyncDeviceStatusRequest::SendSyncDeviceStatusRequest(const std::shared_ptr<Attributes> &request,
    std::optional<ProtocolId> selectedProtocolId, const std::optional<SignedSyncPayload> &payload)
{
    ENSURE_OR_RETURN_DESC(GetDescription(), request != nullptr);
    Attributes wireRequest(*request);

    auto localProfile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    sentProtocolIdList_ =
        selectedProtocolId.has_value() ? std::vector<ProtocolId> { *selectedProtocolId } : localProfile.hostProtocols;

    wireRequest.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(sentProtocolIdList_));

    if (payload.has_value()) {
        EncodeCompanionUserKey(payload->companionUserKey, wireRequest);
        AttachBindingSignatureAttributes(payload->challenge, payload->signature, wireRequest);
    }

    eventCollector_.SetProtocolIdList(ProtocolIdConverter::ToUnderlyingVec(sentProtocolIdList_));
    eventCollector_.EnterWait(HostSyncDeviceStatusStages::WAIT_SYNC_DEVICE_STATUS_REPLY);
    // clang-format off
    if (!SendMessage(MessageType::SYNC_DEVICE_STATUS, std::move(wireRequest),
        [weakSelf = weak_from_this(), request](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleSyncDeviceStatusReply(message, request);
        })) {
        // clang-format on
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        CompleteWithError(ResultCode::COMMUNICATION_ERROR);
    }
}

void HostSyncDeviceStatusRequest::HandleBindingSignatureChallengeResult(ResultCode resultCode,
    const BindingSignatureChallengeResult &challengeResult, const std::shared_ptr<Attributes> &request)
{
    ENSURE_OR_RETURN(request != nullptr);
    if (IsFinished()) {
        return;
    }
    if (resultCode == ResultCode::GENERAL_ERROR || resultCode == ResultCode::TYPE_NOT_SUPPORT) {
        IAM_LOGW("%{public}s challenge round rejected ret=%{public}d, downgrade to v1 sync", GetDescription(),
            static_cast<int32_t>(resultCode));
        SendSyncDeviceStatusRequest(request, ProtocolId::VERSION_1);
        return;
    } else if (resultCode == ResultCode::NOT_ENROLLED) {
        IAM_LOGW("%{public}s challenge round not enrolled, redo round as discovery", GetDescription());
        SendSyncDeviceStatusRequest(request, std::nullopt);
        return;
    } else if (resultCode != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s resolve companion identity failed ret:%{public}d", GetDescription(),
            static_cast<int32_t>(resultCode));
        CompleteWithError(resultCode);
        return;
    }

    auto matched = QueryCompanionStatus(challengeResult.companionUserKey);
    if (matched.has_value() && matched->isValid) {
        if (matched->enrolledProtocolId == ProtocolId::VERSION_2) {
            SignAndSendSyncRequest(challengeResult, *matched, request);
            return;
        }

        IAM_LOGI("%{public}s identity resolved: credential version=V1", GetDescription());
        SendSyncDeviceStatusRequest(request, ProtocolId::VERSION_1);
        return;
    }

    IAM_LOGI("%{public}s identity resolved: unprotected discovery sync", GetDescription());
    SendSyncDeviceStatusRequest(request, std::nullopt);
}

void HostSyncDeviceStatusRequest::SignAndSendSyncRequest(const BindingSignatureChallengeResult &challengeResult,
    const CompanionStatus &matched, const std::shared_ptr<Attributes> &request)
{
    IAM_LOGI("%{public}s identity resolved: credential version=V2, peerDeviceId=%{public}s", GetDescription(),
        GetTruncatedString(companionDeviceKey_.deviceId).c_str());

    HostBindingSignInput signInput = {};
    signInput.templateId = matched.templateId;
    signInput.challenge = challengeResult.challenge;
    HostBindingSignOutput signOutput = {};
    ResultCode ret = GetSecurityAgent().HostBindingSign(signInput, signOutput);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostBindingSign failed ret=%{public}d", GetDescription(), static_cast<int32_t>(ret));
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }

    SendSyncDeviceStatusRequest(request, std::nullopt,
        SignedSyncPayload { challengeResult.companionUserKey, challengeResult.challenge, signOutput.signature });
}

void HostSyncDeviceStatusRequest::HandleSyncDeviceStatusReply(const Attributes &reply,
    const std::shared_ptr<Attributes> &request)
{
    ENSURE_OR_RETURN_DESC(GetDescription(), request != nullptr);
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
        HandlePeerFailureReply(replyData, errorGuard);
        return;
    }

    auto companionStatus = QueryCompanionStatus(replyData.companionDeviceKey.AsUserKey());
    if (ResultCode validationRet = ValidateReplyParameters(replyData); validationRet != ResultCode::SUCCESS) {
        errorGuard.UpdateErrorCode(validationRet);
        return;
    }
    std::vector<Capability> authenticatedCapabilities;
    const bool companionCheckOk = EndCompanionCheck(replyData, companionStatus, authenticatedCapabilities);
    UpdateCompanionUserIdAndSubProfileId(replyData.companionDeviceKey.AsUserKey());

    ProtocolId freshBindingProtocolId = ComputeFreshBindingProtocolId(replyData.companionProtocolIdList);
    if (freshBindingProtocolId == ProtocolId::INVALID) {
        IAM_LOGE("%{public}s no common protocol with the announced support set", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::PROTOCOL_NEGOTIATION_FAILED);
        return;
    }
    ProtocolId selectedProtocolId = freshBindingProtocolId;
    if (companionCheckOk) {
        selectedProtocolId = companionStatus->enrolledProtocolId;
    }
    const std::vector<Capability> &selectedCompanionCapabilityList =
        companionCheckOk ? authenticatedCapabilities : replyData.companionCapabilityList;

    SyncDeviceStatus syncDeviceStatus =
        BuildSyncDeviceStatus(replyData, selectedCompanionCapabilityList, selectedProtocolId, freshBindingProtocolId);

    eventCollector_.SetPeerProtocolIdList(
        ProtocolIdConverter::ToUnderlyingVec(syncDeviceStatus.companionProtocolIdList));
    eventCollector_.SetSelectedProtocolId(ProtocolIdConverter::ToUnderlying(selectedProtocolId));
    eventCollector_.SetSecureProtocolId(static_cast<uint16_t>(syncDeviceStatus.secureProtocolId));

    errorGuard.Cancel();
    CompleteWithSuccess(syncDeviceStatus);
}
void HostSyncDeviceStatusRequest::HandlePeerFailureReply(const SyncDeviceStatusReply &replyData, ErrorGuard &errorGuard)
{
    IAM_LOGE("%{public}s peer sync failed, peerResult=%{public}d", GetDescription(),
        static_cast<int32_t>(replyData.result));
    if (replyData.result == ResultCode::BINDING_SIGNATURE_VERIFY_FAILED ||
        replyData.result == ResultCode::NOT_ENROLLED) {
        InvalidateCompanion(replyData.companionUserKey);
    }
    ResultCode reportCode = (replyData.result == ResultCode::PROTOCOL_NEGOTIATION_FAILED ||
                                replyData.result == ResultCode::SECURE_PROTOCOL_NOT_SUPPORTED ||
                                replyData.result == ResultCode::NOT_ENROLLED ||
                                replyData.result == ResultCode::BINDING_SIGNATURE_VERIFY_FAILED)
        ? replyData.result
        : ResultCode::PEER_SYNC_FAILED;
    errorGuard.UpdateErrorCode(reportCode);
}

SyncDeviceStatus HostSyncDeviceStatusRequest::BuildSyncDeviceStatus(const SyncDeviceStatusReply &reply,
    const std::vector<Capability> &selectedCompanionCapabilityList, ProtocolId selectedProtocolId,
    ProtocolId freshBindingProtocolId) const
{
    SyncDeviceStatus syncDeviceStatus = {};
    syncDeviceStatus.needSync = true;
    syncDeviceStatus.companionProtocolIdList = reply.companionProtocolIdList;
    syncDeviceStatus.companionCapabilityList = selectedCompanionCapabilityList;
    syncDeviceStatus.businessIdList = reply.businessIdList;
    syncDeviceStatus.secureProtocolId = reply.secureProtocolId;
    syncDeviceStatus.deviceUserName = reply.deviceUserName;
    syncDeviceStatus.deviceName = reply.deviceName;
    syncDeviceStatus.deviceUserKey = reply.companionDeviceKey.AsUserKey();
    syncDeviceStatus.deviceSubProfileName = reply.deviceSubProfileName;
    syncDeviceStatus.maxAuthTrustLevel = reply.maxAuthTrustLevel;
    syncDeviceStatus.selectedProtocolId = ProtocolIdConverter::ToUnderlying(selectedProtocolId);
    syncDeviceStatus.freshBindingProtocolId = ProtocolIdConverter::ToUnderlying(freshBindingProtocolId);
    return syncDeviceStatus;
}

std::optional<CompanionStatus> HostSyncDeviceStatusRequest::QueryCompanionStatus(const UserKey &companionUserKey) const
{
    DeviceKey peerKey = companionDeviceKey_;
    peerKey.deviceUserId = companionUserKey.userId;
    peerKey.deviceSubProfileId = companionUserKey.subProfileId;
    return GetCompanionManager().GetCompanionStatus(hostUserKey_, peerKey);
}

void HostSyncDeviceStatusRequest::InvalidateCompanion(const std::optional<UserKey> &companionUserKey)
{
    if (!companionUserKey.has_value()) {
        IAM_LOGW("%{public}s refusal carries no peer identity, skip credential invalidation", GetDescription());
        return;
    }
    auto companionStatus = QueryCompanionStatus(*companionUserKey);
    if (!companionStatus.has_value()) {
        IAM_LOGW("%{public}s peer rejected binding signature, no local credential found", GetDescription());
        return;
    }
    if (!companionStatus->isValid) {
        IAM_LOGI("%{public}s peer rejected binding signature, credential already invalid", GetDescription());
        return;
    }
    IAM_LOGE("%{public}s peer rejected binding signature, invalidate credential", GetDescription());
    GetCompanionManager().SetTemplateInvalid(companionStatus->templateId, "peer rejected binding signature");
}

ResultCode HostSyncDeviceStatusRequest::ValidateReplyParameters(const SyncDeviceStatusReply &reply) const
{
    if (reply.companionProtocolIdList.empty()) {
        return ResultCode::PROTOCOL_NEGOTIATION_FAILED;
    }
    if (IntersectLists(reply.companionProtocolIdList, sentProtocolIdList_).empty()) {
        return ResultCode::PROTOCOL_NEGOTIATION_FAILED;
    }
    return ResultCode::SUCCESS;
}

bool HostSyncDeviceStatusRequest::EndCompanionCheck(const SyncDeviceStatusReply &reply,
    const std::optional<CompanionStatus> &companionStatus, std::vector<Capability> &outCapabilities)
{
    if (!companionStatus) {
        IAM_LOGI("%{public}s companionStatus not exist", GetDescription());
        return false;
    }

    eventCollector_.SetTemplateIdList({ companionStatus->templateId });
    desc_.SetTemplateId(companionStatus->templateId);

    // an invalid credential is treated as not enrolled (no re-report, no verification, no revival)
    if (!companionStatus->isValid) {
        IAM_LOGI("%{public}s credential already invalid, discovery round", GetDescription());
        return false;
    }

    if (reply.companionCheckResponse.empty()) {
        // a bound peer must always prove itself, V1 and V2 alike; silence invalidates
        IAM_LOGE("%{public}s bound peer returned no proof, invalidate", GetDescription());
        GetCompanionManager().SetTemplateInvalid(companionStatus->templateId, "bound peer returned no proof");
        return false;
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
        // invalidation does not fail the round: it still concludes as discovery from this reply
        return false;
    }
    outCapabilities = CapabilityConverter::FromUnderlyingVec(checkOutput.companionCapabilityList);
    return true;
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

void HostSyncDeviceStatusRequest::UpdateCompanionUserIdAndSubProfileId(const UserKey &companionUserKey)
{
    IAM_LOGI("companionUserId: %{public}d, companionSubProfileId: %{public}d", companionUserKey.userId,
        companionUserKey.subProfileId);
    companionDeviceKey_.deviceUserId = companionUserKey.userId;
    companionDeviceKey_.deviceSubProfileId = companionUserKey.subProfileId;
    SetPeerDeviceKey(companionDeviceKey_);
    desc_.SetDeviceId(companionDeviceKey_);
    eventCollector_.SetCompanionUserKey(companionUserKey);
    eventCollector_.SetCompanionDeviceKey(companionDeviceKey_);
}

ProtocolId HostSyncDeviceStatusRequest::ComputeFreshBindingProtocolId(
    const std::vector<ProtocolId> &companionProtocolIdList) const
{
    auto localProfile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    for (const auto &hostProtocol : localProfile.hostProtocols) {
        if (std::find(companionProtocolIdList.begin(), companionProtocolIdList.end(), hostProtocol) !=
            companionProtocolIdList.end()) {
            return hostProtocol;
        }
    }
    IAM_LOGE("%{public}s no common protocol, hostProtocols:%{public}s companionProtocols:%{public}s", GetDescription(),
        GetVectorString(ProtocolIdConverter::ToUnderlyingVec(localProfile.hostProtocols)).c_str(),
        GetVectorString(ProtocolIdConverter::ToUnderlyingVec(companionProtocolIdList)).c_str());
    return ProtocolId::INVALID;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
