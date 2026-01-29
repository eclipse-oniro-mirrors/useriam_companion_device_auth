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

#include "token_auth_message.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "common_message.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
void EncodeTokenAuthRequest(const TokenAuthRequest &request, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, request.hostDeviceKey.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, request.companionUserId);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo);
}

std::optional<TokenAuthRequest> DecodeTokenAuthRequest(const Attributes &attributes)
{
    TokenAuthRequest request = {};
    auto hostKeyOpt = DecodeHostDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(hostKeyOpt.has_value(), std::nullopt);
    request.hostDeviceKey = *hostKeyOpt;
    bool getCompanionUserIdRet =
        attributes.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, request.companionUserId);
    ENSURE_OR_RETURN_VAL(getCompanionUserIdRet, std::nullopt);
    bool getExtraInfoRet = attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo);
    ENSURE_OR_RETURN_VAL(getExtraInfoRet, std::nullopt);
    return request;
}

void EncodeTokenAuthReply(const TokenAuthReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
    if (reply.result != ResultCode::SUCCESS) {
        return;
    }
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.extraInfo);
}

std::optional<TokenAuthReply> DecodeTokenAuthReply(const Attributes &attributes)
{
    TokenAuthReply reply = {};
    int32_t result = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);
    reply.result = static_cast<ResultCode>(result);
    if (reply.result != ResultCode::SUCCESS) {
        return reply;
    }
    bool getExtraInfoRet = attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.extraInfo);
    ENSURE_OR_RETURN_VAL(getExtraInfoRet, std::nullopt);
    return reply;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
