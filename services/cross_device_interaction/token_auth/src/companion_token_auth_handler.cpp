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
#include "security_agent.h"
#include "singleton_manager.h"
#include "token_auth_message.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

CompanionTokenAuthHandler::CompanionTokenAuthHandler() : SyncIncomingMessageHandler(MessageType::TOKEN_AUTH)
{
}

void CompanionTokenAuthHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    IAM_LOGI("start");

    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });

    auto tokenRequestOpt = DecodeTokenAuthRequest(request);
    if (!tokenRequestOpt.has_value()) {
        IAM_LOGE("DecodeTokenAuthRequest failed");
        return;
    }
    const auto &tokenRequest = *tokenRequestOpt;

    auto hostBindingStatus =
        GetHostBindingManager().GetHostBindingStatus(tokenRequest.companionUserId, tokenRequest.hostDeviceKey);
    ENSURE_OR_RETURN(hostBindingStatus.has_value());

    auto secureProtocolId = GetCrossDeviceCommManager().HostGetSecureProtocolId(tokenRequest.hostDeviceKey);
    ENSURE_OR_RETURN(secureProtocolId.has_value());

    CompanionProcessTokenAuthInput input = {};
    input.bindingId = hostBindingStatus->bindingId;
    input.secureProtocolId = secureProtocolId.value();
    input.tokenAuthRequest = tokenRequest.extraInfo;

    CompanionProcessTokenAuthOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionProcessTokenAuth(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("CompanionProcessTokenAuth failed ret=%{public}d", ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    TokenAuthReply replyMsg = { .result = ret, .extraInfo = output.tokenAuthReply };
    EncodeTokenAuthReply(replyMsg, reply);
    errorGuard.Cancel();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
