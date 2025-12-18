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

#include "error_guard.h"
#include "iam_check.h"
#include "iam_logger.h"

#include "companion_manager.h"
#include "revoke_token_message.h"
#include "security_agent.h"
#include "singleton_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

HostRevokeTokenHandler::HostRevokeTokenHandler() : SyncIncomingMessageHandler(MessageType::COMPANION_REVOKE_TOKEN)
{
}

void HostRevokeTokenHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    IAM_LOGI("start");

    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });

    RevokeTokenRequest requestMsg = {};
    bool decodeReqRet = DecodeRevokeTokenRequest(request, requestMsg);
    ENSURE_OR_RETURN(decodeReqRet);

    auto companionStatus =
        GetCompanionManager().GetCompanionStatus(requestMsg.hostUserId, requestMsg.companionDeviceKey);
    if (!companionStatus) {
        IAM_LOGE("GetCompanionStatus failed");
        return;
    }

    HostRevokeTokenInput input = { companionStatus->templateId };
    ResultCode ret = GetSecurityAgent().HostRevokeToken(input);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("HostRevokeToken failed ret=%{public}d", ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    RevokeTokenReply replyMsg = { .result = ResultCode::SUCCESS };
    bool encodeRet = EncodeRevokeTokenReply(replyMsg, reply);
    if (!encodeRet) {
        IAM_LOGE("EncodeRevokeTokenReply failed");
        return;
    }
    errorGuard.Cancel();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
