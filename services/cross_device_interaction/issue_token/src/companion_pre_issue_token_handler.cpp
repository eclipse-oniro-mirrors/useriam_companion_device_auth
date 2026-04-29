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
#include "interaction_desc.h"
#include "issue_token_message.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_COMPANION_PRE_ISSUE_TOKEN_HANDLER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionPreIssueTokenHandler::CompanionPreIssueTokenHandler()
    : AsyncIncomingMessageHandler(MessageType::PRE_ISSUE_TOKEN)
{
}

void CompanionPreIssueTokenHandler::HandleRequest(const Attributes &request, OnMessageReply &onMessageReply)
{
    InteractionDesc desc(HANDLER_PREFIX, "HCIsT");
    IAM_LOGI("%{public}s start", desc.GetCStr());
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), onMessageReply != nullptr);

    ErrorGuard errorGuard([&onMessageReply](ResultCode result) {
        Attributes reply;
        PreIssueTokenReply replyMsg = { .result = result, .extraInfo = {} };
        EncodePreIssueTokenReply(replyMsg, reply);
        onMessageReply(reply);
    });

    std::string connectionName;
    bool getConnectionNameRet = request.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), getConnectionNameRet);
    desc.SetConnectionName(connectionName);

    auto hostDeviceKeyOpt = DecodeHostDeviceKey(request);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), hostDeviceKeyOpt.has_value());

    auto issueTokenRequest = GetRequestFactory().CreateCompanionIssueTokenRequest(connectionName, request,
        std::move(onMessageReply), hostDeviceKeyOpt.value());
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), issueTokenRequest != nullptr);

    bool startRet = GetRequestManager().Start(issueTokenRequest);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), startRet);
    errorGuard.Cancel();
    IAM_LOGI("%{public}s success", desc.GetCStr());
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
