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

#include "add_companion_message.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "common_message.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
bool EncodeInitKeyNegotiationRequest(const InitKeyNegotiationRequest &request, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, request.hostDeviceKey.deviceUserId);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo);
    return true;
}

std::optional<InitKeyNegotiationRequest> DecodeInitKeyNegotiationRequest(const Attributes &attributes)
{
    InitKeyNegotiationRequest request = {};
    auto hostKeyOpt = DecodeHostDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(hostKeyOpt.has_value(), std::nullopt);
    request.hostDeviceKey = *hostKeyOpt;
    if (!attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo)) {
        return std::nullopt;
    }
    return request;
}

bool EncodeInitKeyNegotiationReply(const InitKeyNegotiationReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
    if (reply.result != ResultCode::SUCCESS) {
        return true;
    }
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.extraInfo);
    return true;
}

std::optional<InitKeyNegotiationReply> DecodeInitKeyNegotiationReply(const Attributes &attributes)
{
    int32_t result = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);
    InitKeyNegotiationReply reply = {};
    reply.result = static_cast<ResultCode>(result);
    if (reply.result != ResultCode::SUCCESS) {
        return reply;
    }
    bool getExtraInfoRet = attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.extraInfo);
    ENSURE_OR_RETURN_VAL(getExtraInfoRet, std::nullopt);
    return reply;
}

bool EncodeBeginAddHostBindingRequest(const BeginAddHostBindingRequest &request, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, request.companionUserId);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo);
    return true;
}

std::optional<BeginAddHostBindingRequest> DecodeBeginAddHostBindingRequest(const Attributes &attributes)
{
    BeginAddHostBindingRequest request = {};
    bool getUserIdRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, request.companionUserId);
    ENSURE_OR_RETURN_VAL(getUserIdRet, std::nullopt);
    bool getExtraInfoRet = attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo);
    ENSURE_OR_RETURN_VAL(getExtraInfoRet, std::nullopt);
    return request;
}

bool EncodeBeginAddHostBindingReply(const BeginAddHostBindingReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
    if (reply.result != ResultCode::SUCCESS) {
        return true;
    }
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.extraInfo);
    return true;
}

std::optional<BeginAddHostBindingReply> DecodeBeginAddHostBindingReply(const Attributes &attributes)
{
    BeginAddHostBindingReply reply = {};
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

bool EncodeEndAddHostBindingRequest(const EndAddHostBindingRequest &request, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, request.hostDeviceKey.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, request.companionUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(request.result));
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo);
    return true;
}

std::optional<EndAddHostBindingRequest> DecodeEndAddHostBindingRequest(const Attributes &attributes)
{
    EndAddHostBindingRequest request = {};
    auto hostKeyOpt = DecodeHostDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(hostKeyOpt.has_value(), std::nullopt);
    request.hostDeviceKey = *hostKeyOpt;
    bool getCompanionUserIdRet =
        attributes.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, request.companionUserId);
    ENSURE_OR_RETURN_VAL(getCompanionUserIdRet, std::nullopt);
    int32_t result = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);
    request.result = static_cast<ResultCode>(result);
    bool getExtraInfoRet = attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo);
    ENSURE_OR_RETURN_VAL(getExtraInfoRet, std::nullopt);
    return request;
}

bool EncodeEndAddHostBindingReply(const EndAddHostBindingReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
    return true;
}

std::optional<EndAddHostBindingReply> DecodeEndAddHostBindingReply(const Attributes &attributes)
{
    EndAddHostBindingReply reply = {};
    int32_t result = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);
    reply.result = static_cast<ResultCode>(result);
    return reply;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
