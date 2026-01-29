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

#include "host_pre_obtain_token_handler.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "common_message.h"
#include "error_guard.h"
#include "host_obtain_token_request.h"
#include "obtain_token_message.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostPreObtainTokenHandler::HostPreObtainTokenHandler() : AsyncIncomingMessageHandler(MessageType::PRE_OBTAIN_TOKEN)
{
}

void HostPreObtainTokenHandler::HandleRequest(const Attributes &request, OnMessageReply &onMessageReply)
{
    IAM_LOGI("start");
    ENSURE_OR_RETURN(onMessageReply != nullptr);
    ErrorGuard errorGuard([&onMessageReply](ResultCode result) {
        Attributes reply;
        reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        onMessageReply(reply);
    });

    std::string connectionName;
    bool getConnectionNameRet = request.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName);
    ENSURE_OR_RETURN(getConnectionNameRet);

    auto companionDeviceKeyOpt = DecodeCompanionDeviceKey(request);
    ENSURE_OR_RETURN(companionDeviceKeyOpt.has_value());

    auto obtainTokenRequest = GetRequestFactory().CreateHostObtainTokenRequest(connectionName, request,
        std::move(onMessageReply), *companionDeviceKeyOpt);
    ENSURE_OR_RETURN(obtainTokenRequest != nullptr);

    bool startRet = GetRequestManager().Start(obtainTokenRequest);
    ENSURE_OR_RETURN(startRet);
    errorGuard.Cancel();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
