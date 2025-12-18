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

#include "companion_pre_issue_token_handler.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "common_message.h"
#include "companion_issue_token_request.h"
#include "error_guard.h"
#include "issue_token_message.h"
#include "singleton_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionPreIssueTokenHandler::CompanionPreIssueTokenHandler()
    : AsyncIncomingMessageHandler(MessageType::PRE_ISSUE_TOKEN)
{
}

void CompanionPreIssueTokenHandler::HandleRequest(const Attributes &request, OnMessageReply &onMessageReply)
{
    IAM_LOGI("start");

    ErrorGuard errorGuard([&onMessageReply](ResultCode result) {
        Attributes reply;
        PreIssueTokenReply replyMsg = { .result = result, .extraInfo = {} };
        EncodePreIssueTokenReply(replyMsg, reply);
        onMessageReply(reply);
    });

    std::string connectionName;
    bool getConnectionNameRet = request.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName);
    ENSURE_OR_RETURN(getConnectionNameRet);

    auto hostDeviceKeyOpt = DecodeHostDeviceKey(request);
    ENSURE_OR_RETURN(hostDeviceKeyOpt.has_value());

    auto issueTokenRequest = GetRequestFactory().CreateCompanionIssueTokenRequest(connectionName, request,
        onMessageReply, *hostDeviceKeyOpt);
    ENSURE_OR_RETURN(issueTokenRequest != nullptr);

    bool startRet = GetRequestManager().Start(issueTokenRequest);
    ENSURE_OR_RETURN(startRet);
    errorGuard.Cancel();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
