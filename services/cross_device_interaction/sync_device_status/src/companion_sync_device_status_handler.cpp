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

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"

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
    UserId companionUserId)
{
    syncReply.companionDeviceKey.deviceUserId = companionUserId;
}

std::optional<SyncDeviceStatusReply> CompanionSyncDeviceStatusHandler::BuildSyncDeviceStatusReply(
    UserId companionUserId, const InteractionDesc &desc)
{
    auto profile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    auto userNameOpt = GetUserIdManager().GetActiveUserName();
    if (!userNameOpt.has_value()) {
        IAM_LOGE("%{public}s GetActiveUserName failed", desc.GetCStr());
        return std::nullopt;
    }

    SyncDeviceStatusReply syncReply = {};
    syncReply.result = ResultCode::SUCCESS;
    syncReply.protocolIdList = profile.protocols;
    syncReply.capabilityList = profile.companionCapabilities;
    syncReply.businessIdList = profile.companionSupportedBusinessIds;
    syncReply.secureProtocolId = profile.companionSecureProtocolId;
    SetCompanionDeviceKeyUserId(syncReply, companionUserId);
    syncReply.deviceUserName = GetUserIdManager().GetActiveUserTypeName() + ":" + userNameOpt.value();
    syncReply.deviceName = GetSystemSettingsManager().GetSettingsValue(SettingKey::DisplayDeviceName);
    // The per-user display name may be unset before first configuration; fall back to the device model
    // sysparam so the name is never empty on the wire.
    if (syncReply.deviceName.empty()) {
        syncReply.deviceName = GetSystemParamManager().GetParam("const.product.name", "");
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

    auto companionUserId = QueryActiveUserId();
    if (companionUserId == INVALID_USER_ID) {
        IAM_LOGE("%{public}s GetActiveUserId failed", desc.GetCStr());
        return;
    }

    auto syncReplyOpt = BuildSyncDeviceStatusReply(companionUserId, desc);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), syncReplyOpt.has_value());
    SyncDeviceStatusReply syncReply = std::move(*syncReplyOpt);

    auto hostBindingStatus = QueryHostBindingStatus(companionUserId, syncRequest.hostDeviceKey);
    if (hostBindingStatus.has_value()) {
        desc.SetBindingId(hostBindingStatus->bindingId);
        eventCollector.SetBindingId(hostBindingStatus->bindingId);
        bool ret = CompanionProcessCheck(*hostBindingStatus, syncRequest, syncReply.companionCheckResponse, desc);
        if (!ret) {
            IAM_LOGE("%{public}s CompanionProcessCheck failed, clear companionCheckResponse", desc.GetCStr());
            syncReply.companionCheckResponse.clear();
        }
    }

    EncodeSyncDeviceStatusReply(syncReply, reply);
    errorGuard.Cancel();
    eventCollector.Report(ResultCode::SUCCESS);
    IAM_LOGI("%{public}s success", desc.GetCStr());
}

CompanionProcessCheckInput CompanionSyncDeviceStatusHandler::BuildCompanionProcessCheckInput(
    const HostBindingStatus &hostBindingStatus, const SyncDeviceStatusRequest &syncRequest,
    SecureProtocolId secureProtocolId)
{
    CompanionProcessCheckInput input = {};
    input.bindingId = hostBindingStatus.bindingId;
    input.protocolList = ProtocolIdConverter::ToUnderlyingVec(syncRequest.protocolIdList);
    input.capabilityList = CapabilityConverter::ToUnderlyingVec(syncRequest.capabilityList);
    input.secureProtocolId = secureProtocolId;
    input.salt = syncRequest.salt;
    input.challenge = syncRequest.challenge;
    return input;
}

bool CompanionSyncDeviceStatusHandler::CompanionProcessCheck(const HostBindingStatus &hostBindingStatus,
    const SyncDeviceStatusRequest &syncRequest, std::vector<uint8_t> &outCompanionCheckResponse,
    const InteractionDesc &desc)
{
    auto profile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    CompanionProcessCheckInput input =
        BuildCompanionProcessCheckInput(hostBindingStatus, syncRequest, profile.companionSecureProtocolId);

    CompanionProcessCheckOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionProcessCheck(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionProcessCheck failed ret=%{public}d", desc.GetCStr(), ret);
        return false;
    }
    outCompanionCheckResponse.swap(output.companionCheckResponse);
    return true;
}
UserId CompanionSyncDeviceStatusHandler::QueryActiveUserId()
{
    return GetUserIdManager().GetActiveUserId();
}

std::optional<HostBindingStatus> CompanionSyncDeviceStatusHandler::QueryHostBindingStatus(UserId companionUserId,
    const DeviceKey &hostDeviceKey)
{
    return GetHostBindingManager().GetHostBindingStatus(companionUserId, hostDeviceKey);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
