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

#include "companion_sync_device_status_handler.h"

#include <algorithm>

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "adapter_manager.h"
#include "common_message.h"
#include "error_guard.h"
#include "interaction_desc.h"
#include "interaction_event_collector.h"
#include "service_common.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_COMPANION_SYNC_DEVICE_STATUS_HANDLER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionSyncDeviceStatusHandler::CompanionSyncDeviceStatusHandler()
    : SyncIncomingMessageHandler(MessageType::SYNC_DEVICE_STATUS)
{
}

void CompanionSyncDeviceStatusHandler::SetCompanionDeviceKeyUserId(SyncDeviceStatusReply &syncReply,
    const UserKey &companionUserKey)
{
    syncReply.companionDeviceKey.deviceUserId = companionUserKey.userId;
    syncReply.companionDeviceKey.deviceSubProfileId = companionUserKey.subProfileId;
}

std::optional<SyncDeviceStatusReply> CompanionSyncDeviceStatusHandler::BuildSyncDeviceStatusReply(
    const UserKey &companionUserKey, const LocalDeviceProfile &localProfile, const InteractionDesc &desc)
{
    auto userNameOpt = GetUserKeyManager().GetActiveUserName();
    if (!userNameOpt.has_value()) {
        IAM_LOGE("%{public}s GetActiveUserName failed", desc.GetCStr());
        return std::nullopt;
    }

    SyncDeviceStatusReply syncReply = {};
    syncReply.result = ResultCode::SUCCESS;
    // Unbound discovery round: no proof exists, the proof-list field degenerates to the full
    // announcement (legacy hosts negotiate on it). A bound round narrows it in ProcessBindingCheck.
    syncReply.companionProofProtocolIdList = localProfile.companionProtocols;
    syncReply.companionSupportedProtocolIdList = localProfile.companionProtocols;
    syncReply.companionCapabilityList = localProfile.companionCapabilities;
    syncReply.businessIdList = localProfile.companionSupportedBusinessIds;
    syncReply.secureProtocolId = localProfile.companionSecureProtocolId;
#ifdef ENABLE_COMPANION_V2
    syncReply.maxAuthTrustLevel = ATL2;
#endif
    SetCompanionDeviceKeyUserId(syncReply, companionUserKey);
    syncReply.deviceUserName = GetUserKeyManager().GetActiveUserTypeName() + ":" + userNameOpt.value();
    syncReply.deviceName = GetSystemSettingsManager().GetSettingsValue(SettingKey::DisplayDeviceName);
    // The per-user display name may be unset before first configuration; fall back to the device model
    // sysparam so the name is never empty on the wire.
    if (syncReply.deviceName.empty()) {
        syncReply.deviceName = GetSystemParamManager().GetParam("const.product.name", "");
    }
    auto subProfileNameOpt = GetUserKeyManager().GetSubProfileName(
        UserKey { companionUserKey.userId, syncReply.companionDeviceKey.deviceSubProfileId });
    if (subProfileNameOpt.has_value()) {
        syncReply.deviceSubProfileName = subProfileNameOpt.value();
    }
    return syncReply;
}

void CompanionSyncDeviceStatusHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    InteractionDesc desc(HANDLER_PREFIX, "HCSync");
    IAM_LOGI("%{public}s start", desc.GetCStr());
    LogTraceGuard guard;

    InteractionEventCollector eventCollector("HCSync");
    ErrorGuard errorGuard([&reply, &eventCollector](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
        eventCollector.Report(result);
    });

    std::string connectionName;
    if (request.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName)) {
        desc.SetConnectionName(connectionName);
        eventCollector.SetConnectionName(connectionName);
    }

    auto syncRequestOpt = DecodeSyncDeviceStatusRequest(request);
    if (!syncRequestOpt.has_value()) {
        IAM_LOGE("%{public}s DecodeSyncDeviceStatusRequest failed", desc.GetCStr());
        return;
    }
    const auto &syncRequest = *syncRequestOpt;

    auto companionUserKey = QueryActiveUserKey();
    if (companionUserKey.userId == INVALID_USER_ID) {
        IAM_LOGE("%{public}s GetUnlockedActiveUserkey failed", desc.GetCStr());
        return;
    }
    EncodeCompanionUserKey(companionUserKey, reply);

    auto localProfile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    bool assertedLocalIdentity =
        syncRequest.companionUserKey.has_value() && *syncRequest.companionUserKey == companionUserKey;
    auto hostBindingStatus = QueryHostBindingStatus(companionUserKey, syncRequest.hostDeviceKey);
    if (!hostBindingStatus.has_value() && assertedLocalIdentity) {
        errorGuard.UpdateErrorCode(ResultCode::NOT_ENROLLED);
        return;
    }
    GateBindingProofAgainstEnrolledProtocol(syncRequest, desc, eventCollector, hostBindingStatus);

    ResultCode negotiateRet = NegotiateSyncParameters(syncRequest, localProfile, hostBindingStatus, errorGuard);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), negotiateRet == ResultCode::SUCCESS);

    auto syncReplyOpt = BuildSyncDeviceStatusReply(companionUserKey, localProfile, desc);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), syncReplyOpt.has_value());
    auto &syncReply = *syncReplyOpt;

    // clang-format off
    ResultCode checkRet = ProcessBindingCheck(syncRequest, hostBindingStatus, localProfile, desc, syncReply);
    // clang-format on
    errorGuard.UpdateErrorCode(checkRet);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), checkRet == ResultCode::SUCCESS);

    EncodeSyncDeviceStatusReply(syncReply, reply);
    PublishPeerSyncedEvent(syncRequest.hostDeviceKey);

    errorGuard.Cancel();
    eventCollector.Report(ResultCode::SUCCESS);
    IAM_LOGI("%{public}s success", desc.GetCStr());
}

void CompanionSyncDeviceStatusHandler::PublishPeerSyncedEvent(const DeviceKey &hostDeviceKey)
{
    Attributes peerSyncedEvent {};
    peerSyncedEvent.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey.deviceId);
    peerSyncedEvent.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(hostDeviceKey.idType));
    GetEventBus().Publish(EventType::PEER_SYNCED, peerSyncedEvent.Serialize());
}

void CompanionSyncDeviceStatusHandler::GateBindingProofAgainstEnrolledProtocol(
    const SyncDeviceStatusRequest &syncRequest, InteractionDesc &desc, InteractionEventCollector &eventCollector,
    std::optional<HostBindingStatus> &hostBindingStatus)
{
    if (!hostBindingStatus.has_value()) {
        return;
    }
    desc.SetBindingId(hostBindingStatus->bindingId);
    eventCollector.SetBindingId(hostBindingStatus->bindingId);
    bool proofPresent = syncRequest.bindingSignatureProof.has_value();
    bool isV2Binding = hostBindingStatus->enrolledProtocolId == ProtocolId::VERSION_2;
    if (proofPresent != isV2Binding) {
        IAM_LOGI("%{public}s sync proof mismatches enrolled protocol (proof=%{public}d, enrolled=%{public}hu), "
                 "treat as unbound discovery round",
            desc.GetCStr(), proofPresent, static_cast<uint16_t>(hostBindingStatus->enrolledProtocolId));
        hostBindingStatus = std::nullopt;
    }
}

ResultCode CompanionSyncDeviceStatusHandler::ProcessBindingCheck(const SyncDeviceStatusRequest &syncRequest,
    const std::optional<HostBindingStatus> &hostBindingStatus, const LocalDeviceProfile &localProfile,
    const InteractionDesc &desc, SyncDeviceStatusReply &syncReply)
{
    if (!hostBindingStatus.has_value()) {
        return ResultCode::SUCCESS;
    }
    // The proof lists what the host offered and this device supports: a legacy host only ever offers
    // VERSION_1, so the proof never carries a value the legacy host's Rust rejects. The outer list
    // mirrors it.
    std::vector<ProtocolId> companionProofProtocolIdList =
        IntersectLists(syncRequest.hostProtocolIdList, localProfile.companionProtocols);
    syncReply.companionProofProtocolIdList = companionProofProtocolIdList;
    BindingSignatureProof bindingSignatureProof = syncRequest.bindingSignatureProof.value_or(BindingSignatureProof {});
    CompanionProcessCheckInput input = BuildCompanionProcessCheckInput(*hostBindingStatus, syncRequest,
        companionProofProtocolIdList, localProfile, bindingSignatureProof);
    ResultCode checkRet = CompanionProcessCheck(input, desc, syncReply.companionCheckResponse);
    if (checkRet != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionProcessCheck failed ret=%{public}d", desc.GetCStr(), checkRet);
    }
    return checkRet;
}

ResultCode CompanionSyncDeviceStatusHandler::NegotiateSyncParameters(const SyncDeviceStatusRequest &syncRequest,
    const LocalDeviceProfile &localProfile, const std::optional<HostBindingStatus> &hostBindingStatus,
    ErrorGuard &errorGuard)
{
    std::vector<ProtocolId> commonProtocolIdList =
        IntersectLists(syncRequest.hostProtocolIdList, localProfile.companionProtocols);
    if (commonProtocolIdList.empty()) {
        IAM_LOGE("protocol negotiation failed, offered protocol count=%{public}zu, local supported count=%{public}zu",
            syncRequest.hostProtocolIdList.size(), localProfile.companionProtocols.size());
        errorGuard.UpdateErrorCode(ResultCode::PROTOCOL_NEGOTIATION_FAILED);
        return ResultCode::PROTOCOL_NEGOTIATION_FAILED;
    }
    if (hostBindingStatus.has_value()) {
        const auto &enrolledProtocolId = hostBindingStatus->enrolledProtocolId;
        if (std::find(commonProtocolIdList.begin(), commonProtocolIdList.end(), enrolledProtocolId) ==
            commonProtocolIdList.end()) {
            IAM_LOGE("enrolled protocol %{public}hu not in negotiated protocol list, bindingId=%{public}s",
                static_cast<uint16_t>(enrolledProtocolId), GET_MASKED_NUM_STRING(hostBindingStatus->bindingId).c_str());
            errorGuard.UpdateErrorCode(ResultCode::PROTOCOL_NEGOTIATION_FAILED);
            return ResultCode::PROTOCOL_NEGOTIATION_FAILED;
        }
    }
    return ResultCode::SUCCESS;
}

CompanionProcessCheckInput CompanionSyncDeviceStatusHandler::BuildCompanionProcessCheckInput(
    const HostBindingStatus &hostBindingStatus, const SyncDeviceStatusRequest &syncRequest,
    const std::vector<ProtocolId> &companionProofProtocolIdList, const LocalDeviceProfile &localProfile,
    const BindingSignatureProof &bindingSignatureProof)
{
    CompanionProcessCheckInput input = {};
    input.bindingId = hostBindingStatus.bindingId;
    input.companionProofProtocolList = ProtocolIdConverter::ToUnderlyingVec(companionProofProtocolIdList);
    input.companionCapabilityList = CapabilityConverter::ToUnderlyingVec(localProfile.companionCapabilities);
    input.secureProtocolId = localProfile.companionSecureProtocolId;
    input.salt = syncRequest.salt;
    input.challenge = syncRequest.challenge;
    input.bindingSignatureProof = bindingSignatureProof;
    return input;
}

ResultCode CompanionSyncDeviceStatusHandler::CompanionProcessCheck(const CompanionProcessCheckInput &input,
    const InteractionDesc &desc, std::vector<uint8_t> &outCompanionCheckResponse)
{
    CompanionProcessCheckOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionProcessCheck(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionProcessCheck failed ret=%{public}d", desc.GetCStr(), ret);
        return ret;
    }
    if (output.companionCheckResponse.empty()) {
        IAM_LOGE("%{public}s CompanionProcessCheck succeeded without a proof", desc.GetCStr());
        return ResultCode::GENERAL_ERROR;
    }
    outCompanionCheckResponse.swap(output.companionCheckResponse);
    return ResultCode::SUCCESS;
}

UserKey CompanionSyncDeviceStatusHandler::QueryActiveUserKey()
{
    return GetUserKeyManager().GetUnlockedActiveUserkey();
}

std::optional<HostBindingStatus> CompanionSyncDeviceStatusHandler::QueryHostBindingStatus(
    const UserKey &companionUserKey, const DeviceKey &hostDeviceKey)
{
    return GetHostBindingManager().GetHostBindingStatus(companionUserKey, hostDeviceKey);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
