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

#include "auth_maintain_state_change_message.h"

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
bool EncodeAuthMaintainStateChangeRequest(const AuthMaintainStateChangeRequestMsg &request, Attributes &attributes)
{
    attributes.SetBoolValue(Attributes::ATTR_CDA_SA_AUTH_STATE_MAINTAIN, request.authMaintainState);
    return true;
}

std::optional<AuthMaintainStateChangeRequestMsg> DecodeAuthMaintainStateChangeRequest(const Attributes &attributes)
{
    AuthMaintainStateChangeRequestMsg request = {};
    bool getRet = attributes.GetBoolValue(Attributes::ATTR_CDA_SA_AUTH_STATE_MAINTAIN, request.authMaintainState);
    ENSURE_OR_RETURN_VAL(getRet, std::nullopt);
    return request;
}

bool EncodeAuthMaintainStateChangeReply(const AuthMaintainStateChangeReplyMsg &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
    return true;
}

std::optional<AuthMaintainStateChangeReplyMsg> DecodeAuthMaintainStateChangeReply(const Attributes &attributes)
{
    AuthMaintainStateChangeReplyMsg reply = {};
    int32_t result = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);
    reply.result = static_cast<ResultCode>(result);
    return reply;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
