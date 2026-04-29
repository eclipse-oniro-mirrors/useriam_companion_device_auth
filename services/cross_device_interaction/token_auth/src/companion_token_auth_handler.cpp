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

#include "companion_token_auth_handler.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "cross_device_comm_manager.h"
#include "error_guard.h"
#include "host_binding_manager.h"
#include "interaction_desc.h"
#include "interaction_event_collector.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "token_auth_message.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_COMPANION_TOKEN_AUTH_HANDLER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

CompanionTokenAuthHandler::CompanionTokenAuthHandler() : SyncIncomingMessageHandler(MessageType::TOKEN_AUTH)
{
}

void CompanionTokenAuthHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    InteractionDesc desc(HANDLER_PREFIX, "HCTkA");
    IAM_LOGI("%{public}s start", desc.GetCStr());

    InteractionEventCollector eventCollector("HCTkA");
    ErrorGuard errorGuard([&reply, &eventCollector](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
        eventCollector.Report(result);
    });

    std::string connectionName;
    if (request.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName)) {
        desc.SetConnectionName(connectionName);
        eventCollector.SetConnectionName(connectionName);
    }

    auto tokenRequestOpt = DecodeTokenAuthRequest(request);
    if (!tokenRequestOpt.has_value()) {
        IAM_LOGE("%{public}s DecodeTokenAuthRequest failed", desc.GetCStr());
        return;
    }
    const auto &tokenRequest = *tokenRequestOpt;

    if (!GetCrossDeviceCommManager().IsAuthMaintainActive()) {
        IAM_LOGE("%{public}s local auth maintain inactive", desc.GetCStr());
        return;
    }

    auto hostBindingStatus =
        GetHostBindingManager().GetHostBindingStatus(tokenRequest.companionUserId, tokenRequest.hostDeviceKey);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), hostBindingStatus.has_value());
    desc.SetBindingId(hostBindingStatus->bindingId);
    eventCollector.SetBindingId(hostBindingStatus->bindingId);

    auto secureProtocolId = GetCrossDeviceCommManager().CompanionGetSecureProtocolId();

    CompanionProcessTokenAuthInput input = {};
    input.bindingId = hostBindingStatus->bindingId;
    input.secureProtocolId = secureProtocolId;
    input.tokenAuthRequest = tokenRequest.extraInfo;

    CompanionProcessTokenAuthOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionProcessTokenAuth(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionProcessTokenAuth failed ret=%{public}d", desc.GetCStr(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    TokenAuthReply replyMsg = { .result = ret, .extraInfo = output.tokenAuthReply };
    EncodeTokenAuthReply(replyMsg, reply);
    errorGuard.Cancel();
    eventCollector.Report(ResultCode::SUCCESS);
    IAM_LOGI("%{public}s success", desc.GetCStr());
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
