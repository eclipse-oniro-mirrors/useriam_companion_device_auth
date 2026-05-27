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

#include "host_revoke_token_handler.h"

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "companion_manager.h"
#include "error_guard.h"
#include "interaction_desc.h"
#include "interaction_event_collector.h"
#include "revoke_token_message.h"
#include "security_agent.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_REVOKE_TOKEN_HANDLER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

HostRevokeTokenHandler::HostRevokeTokenHandler() : SyncIncomingMessageHandler(MessageType::COMPANION_REVOKE_TOKEN)
{
}

void HostRevokeTokenHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    InteractionDesc desc(HANDLER_PREFIX, "HHRvT");
    IAM_LOGI("%{public}s start", desc.GetCStr());
    LogTraceGuard guard;

    InteractionEventCollector eventCollector("HHRvT");
    ErrorGuard errorGuard([&reply, &eventCollector](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
        eventCollector.Report(result);
    });

    std::string connectionName;
    if (request.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName)) {
        desc.SetConnectionName(connectionName);
        eventCollector.SetConnectionName(connectionName);
    }

    auto requestMsgOpt = DecodeRevokeTokenRequest(request);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), requestMsgOpt.has_value());
    const auto &requestMsg = *requestMsgOpt;

    auto companionStatus =
        GetCompanionManager().GetCompanionStatus(requestMsg.hostUserId, requestMsg.companionDeviceKey);
    if (!companionStatus) {
        IAM_LOGE("%{public}s GetCompanionStatus failed", desc.GetCStr());
        return;
    }

    desc.SetTemplateId(companionStatus->templateId);
    desc.SetDeviceId(requestMsg.companionDeviceKey);
    eventCollector.SetTemplateIdList({ companionStatus->templateId });
    GetCompanionManager().SetCompanionTokenAuthAtl(companionStatus->templateId, std::nullopt);

    RevokeTokenReply replyMsg = { .result = ResultCode::SUCCESS };
    EncodeRevokeTokenReply(replyMsg, reply);
    errorGuard.Cancel();
    eventCollector.Report(ResultCode::SUCCESS);
    IAM_LOGI("%{public}s success", desc.GetCStr());
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
