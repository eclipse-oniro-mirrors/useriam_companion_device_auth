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

#include "companion_start_delegate_auth_handler.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "common_message.h"
#include "delegate_auth_message.h"
#include "error_guard.h"
#include "interaction_desc.h"
#include "request_manager.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_COMPANION_START_DELEGATE_AUTH_HANDLER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

CompanionStartDelegateAuthHandler::CompanionStartDelegateAuthHandler()
    : SyncIncomingMessageHandler(MessageType::START_DELEGATE_AUTH)
{
}

void CompanionStartDelegateAuthHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    InteractionDesc desc(HANDLER_PREFIX, "HCDlA");
    IAM_LOGI("%{public}s start", desc.GetCStr());

    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });

    std::string connectionName;
    bool getConnectionNameRet = request.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), getConnectionNameRet);
    desc.SetConnectionName(connectionName);

    auto startRequestOpt = DecodeStartDelegateAuthRequest(request);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), startRequestOpt.has_value());

    auto delegateAuthRequest = GetRequestFactory().CreateCompanionDelegateAuthRequest(connectionName,
        startRequestOpt->companionUserId, startRequestOpt->hostDeviceKey, startRequestOpt->extraInfo);
    ENSURE_OR_RETURN_DESC(desc.GetCStr(), delegateAuthRequest != nullptr);

    bool startRet = GetRequestManager().Start(delegateAuthRequest);
    if (!startRet) {
        IAM_LOGE("%{public}s requestManager Start failed", desc.GetCStr());
        return;
    }

    StartDelegateAuthReply replyMsg = { .result = ResultCode::SUCCESS };
    EncodeStartDelegateAuthReply(replyMsg, reply);
    errorGuard.Cancel();
    IAM_LOGI("%{public}s success", desc.GetCStr());
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
