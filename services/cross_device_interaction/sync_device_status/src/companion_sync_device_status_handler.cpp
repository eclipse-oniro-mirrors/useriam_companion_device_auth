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
#include "iam_logger.h"

#include "adapter_manager.h"
#include "common_message.h"
#include "error_guard.h"
#include "service_common.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionSyncDeviceStatusHandler::CompanionSyncDeviceStatusHandler()
    : SyncIncomingMessageHandler(MessageType::SYNC_DEVICE_STATUS)
{
}

void CompanionSyncDeviceStatusHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    IAM_LOGI("start");

    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });

    auto syncRequestOpt = DecodeSyncDeviceStatusRequest(request);
    if (!syncRequestOpt.has_value()) {
        IAM_LOGE("DecodeSyncDeviceStatusRequest failed");
        return;
    }
    const auto &syncRequest = *syncRequestOpt;

    auto companionUserId = GetUserIdManager().GetActiveUserId();
    if (companionUserId == INVALID_USER_ID) {
        IAM_LOGE("GetActiveUserId failed");
        return;
    }

    auto profile = GetCrossDeviceCommManager().GetLocalDeviceProfile();

    SyncDeviceStatusReply syncReply = {};
    syncReply.result = ResultCode::SUCCESS;
    syncReply.protocolIdList = profile.protocols;
    syncReply.capabilityList = profile.capabilities;
    syncReply.secureProtocolId = profile.companionSecureProtocolId;
    syncReply.companionDeviceKey.deviceUserId = companionUserId;
    syncReply.deviceUserName = GetUserIdManager().GetActiveUserName();

    auto hostBindingStatus = GetHostBindingManager().GetHostBindingStatus(companionUserId, syncRequest.hostDeviceKey);
    if (hostBindingStatus.has_value()) {
        bool ret = CompanionProcessCheck(*hostBindingStatus, syncRequest, syncReply.companionCheckResponse);
        if (!ret) {
            IAM_LOGE("CompanionProcessCheck failed");
            return;
        }
    }

    bool encodeRet = EncodeSyncDeviceStatusReply(syncReply, reply);
    if (!encodeRet) {
        IAM_LOGE("EncodeSyncDeviceStatusReply failed");
        return;
    }
    errorGuard.Cancel();
}

bool CompanionSyncDeviceStatusHandler::CompanionProcessCheck(const HostBindingStatus &hostBindingStatus,
    const SyncDeviceStatusRequest &syncRequest, std::vector<uint8_t> &outCompanionCheckResponse)
{
    CompanionProcessCheckInput input = {};
    input.bindingId = hostBindingStatus.bindingId;
    input.capabilityList = CapabilityConverter::ToUnderlyingVec(syncRequest.capabilityList);
    input.secureProtocolId = GetCrossDeviceCommManager().GetLocalDeviceProfile().companionSecureProtocolId;
    input.salt = syncRequest.salt;
    input.challenge = syncRequest.challenge;

    CompanionProcessCheckOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionProcessCheck(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("CompanionProcessCheck failed ret=%{public}d", ret);
        return false;
    }
    outCompanionCheckResponse.swap(output.companionCheckResponse);
    return true;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
