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

#include "host_request_resync_handler.h"

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "cross_device_common.h"
#include "error_guard.h"
#include "interaction_desc.h"
#include "interaction_event_collector.h"
#include "resync_device_status_message.h"
#include "service_common.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_REQUEST_RESYNC_HANDLER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

HostRequestResyncHandler::HostRequestResyncHandler() : SyncIncomingMessageHandler(MessageType::REQUEST_DEVICE_RESYNC)
{
}

void HostRequestResyncHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    InteractionDesc desc(HANDLER_PREFIX, "HHResync");
    IAM_LOGI("%{public}s start", desc.GetCStr());
    LogTraceGuard guard;

    InteractionEventCollector eventCollector("HHResync");
    ErrorGuard errorGuard([&reply, &eventCollector](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
        eventCollector.Report(result);
    });

    std::string connectionName;
    if (request.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName)) {
        desc.SetConnectionName(connectionName);
        eventCollector.SetConnectionName(connectionName);
    }

    auto requestMsgOpt = DecodeRequestDeviceResyncRequest(request);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), requestMsgOpt.has_value());
    const auto &companionDeviceKey = requestMsgOpt->companionDeviceKey;

    desc.SetDeviceId(companionDeviceKey);
    eventCollector.SetCompanionDeviceKey(companionDeviceKey);

    // The sender's DeviceKey is authenticated by the message router; ask the device status
    // manager to re-sync this physical device immediately.
    GetCrossDeviceCommManager().TriggerDeviceSync(companionDeviceKey);

    RequestDeviceResyncReply replyMsg = { .result = ResultCode::SUCCESS };
    EncodeRequestDeviceResyncReply(replyMsg, reply);
    errorGuard.Cancel();
    eventCollector.Report(ResultCode::SUCCESS);
    IAM_LOGI("%{public}s success", desc.GetCStr());
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
