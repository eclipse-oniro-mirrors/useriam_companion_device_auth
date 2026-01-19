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

#include "companion_init_key_negotiation_handler.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "add_companion_message.h"
#include "common_message.h"
#include "companion_add_companion_request.h"
#include "error_guard.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionInitKeyNegotiationHandler::CompanionInitKeyNegotiationHandler()
    : AsyncIncomingMessageHandler(MessageType::INIT_KEY_NEGOTIATION)
{
}

void CompanionInitKeyNegotiationHandler::HandleRequest(const Attributes &request, OnMessageReply &onMessageReply)
{
    IAM_LOGI("start");

    ErrorGuard errorGuard([&onMessageReply](ResultCode result) {
        Attributes reply;
        reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        onMessageReply(reply);
    });

    std::string connectionName;
    bool getConnectionNameRet = request.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName);
    ENSURE_OR_RETURN(getConnectionNameRet);

    auto hostDeviceKeyOpt = DecodeHostDeviceKey(request);
    ENSURE_OR_RETURN(hostDeviceKeyOpt.has_value());

    auto addCompanionRequest = GetRequestFactory().CreateCompanionAddCompanionRequest(connectionName, request,
        onMessageReply, *hostDeviceKeyOpt);
    ENSURE_OR_RETURN(addCompanionRequest != nullptr);

    bool startRet = GetRequestManager().Start(addCompanionRequest);
    ENSURE_OR_RETURN(startRet);

    errorGuard.Cancel();

    IAM_LOGI("success");
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
