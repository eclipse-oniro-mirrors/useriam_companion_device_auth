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

#include "revoke_token_message.h"

#include <optional>

#include "iam_check.h"
#include "iam_logger.h"

#include "common_message.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
bool EncodeRevokeTokenRequest(const RevokeTokenRequest &request, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, request.hostUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, request.companionDeviceKey.deviceUserId);
    return true;
}

std::optional<RevokeTokenRequest> DecodeRevokeTokenRequest(const Attributes &attributes)
{
    RevokeTokenRequest request;
    bool getHostUserIdRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, request.hostUserId);
    ENSURE_OR_RETURN_VAL(getHostUserIdRet, std::nullopt);
    auto companionKeyOpt = DecodeCompanionDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(companionKeyOpt.has_value(), std::nullopt);
    request.companionDeviceKey = *companionKeyOpt;
    return request;
}

bool EncodeRevokeTokenReply(const RevokeTokenReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
    return true;
}

std::optional<RevokeTokenReply> DecodeRevokeTokenReply(const Attributes &attributes)
{
    int32_t result = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);

    RevokeTokenReply reply;
    reply.result = static_cast<ResultCode>(result);
    return reply;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
