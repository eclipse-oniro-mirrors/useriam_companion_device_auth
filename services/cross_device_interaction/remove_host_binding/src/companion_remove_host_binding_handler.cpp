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

#include "companion_remove_host_binding_handler.h"

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "error_guard.h"
#include "interaction_desc.h"
#include "interaction_event_collector.h"
#include "remove_host_binding_message.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_COMPANION_REMOVE_HOST_BINDING_HANDLER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionRemoveHostBindingHandler::CompanionRemoveHostBindingHandler()
    : SyncIncomingMessageHandler(MessageType::REMOVE_HOST_BINDING)
{
}

void CompanionRemoveHostBindingHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    InteractionDesc desc(HANDLER_PREFIX, "HCRmB");
    IAM_LOGI("%{public}s start", desc.GetCStr());
    LogTraceGuard guard;

    InteractionEventCollector eventCollector("HCRmB");
    ErrorGuard errorGuard([&reply, &eventCollector](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
        eventCollector.Report(result);
    });

    std::string connectionName;
    if (request.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName)) {
        desc.SetConnectionName(connectionName);
        eventCollector.SetConnectionName(connectionName);
    }

    auto requestMsgOpt = DecodeRemoveHostBindingRequest(request);
    if (!requestMsgOpt.has_value()) {
        IAM_LOGE("%{public}s DecodeRemoveHostBindingRequest failed", desc.GetCStr());
        return;
    }
    const auto &requestMsg = *requestMsgOpt;

    auto hostBindingStatus =
        GetHostBindingManager().GetHostBindingStatus(requestMsg.companionUserId, requestMsg.hostDeviceKey);
    if (hostBindingStatus.has_value()) {
        desc.SetBindingId(hostBindingStatus->bindingId);
        eventCollector.SetBindingId(hostBindingStatus->bindingId);
    }

    ResultCode ret = GetHostBindingManager().RemoveHostBinding(requestMsg.companionUserId, requestMsg.hostDeviceKey);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s RemoveHostBinding failed ret=%{public}d", desc.GetCStr(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    RemoveHostBindingReply replyMsg = { .result = ResultCode::SUCCESS };
    EncodeRemoveHostBindingReply(replyMsg, reply);
    errorGuard.Cancel();
    eventCollector.Report(ResultCode::SUCCESS);
    IAM_LOGI("%{public}s success", desc.GetCStr());
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
