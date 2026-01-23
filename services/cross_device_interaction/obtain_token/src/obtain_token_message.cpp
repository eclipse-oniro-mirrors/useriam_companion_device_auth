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

#include "obtain_token_message.h"

#include <optional>

#include "iam_check.h"
#include "iam_logger.h"

#include "common_message.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
bool EncodePreObtainTokenRequest(const PreObtainTokenRequest &request, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, request.hostUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, request.companionDeviceKey.deviceUserId);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo);
    return true;
}

std::optional<PreObtainTokenRequest> DecodePreObtainTokenRequest(const Attributes &attributes)
{
    PreObtainTokenRequest request {};
    bool getHostUserIdRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, request.hostUserId);
    ENSURE_OR_RETURN_VAL(getHostUserIdRet, std::nullopt);
    auto companionDeviceKeyOpt = DecodeCompanionDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(companionDeviceKeyOpt.has_value(), std::nullopt);
    request.companionDeviceKey = *companionDeviceKeyOpt;
    bool getExtraInfoRet = attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo);
    ENSURE_OR_RETURN_VAL(getExtraInfoRet, std::nullopt);
    return request;
}

bool EncodePreObtainTokenReply(const PreObtainTokenReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, reply.result);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.extraInfo);
    return true;
}

std::optional<PreObtainTokenReply> DecodePreObtainTokenReply(const Attributes &attributes)
{
    PreObtainTokenReply reply {};
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, reply.result);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);
    if (reply.result != ResultCode::SUCCESS) {
        return reply;
    }
    bool getExtraInfoRet = attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.extraInfo);
    ENSURE_OR_RETURN_VAL(getExtraInfoRet, std::nullopt);
    return reply;
}

bool EncodeObtainTokenRequest(const ObtainTokenRequest &request, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, request.hostUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, request.companionDeviceKey.deviceUserId);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo);
    return true;
}

std::optional<ObtainTokenRequest> DecodeObtainTokenRequest(const Attributes &attributes)
{
    ObtainTokenRequest request {};
    bool getHostUserIdRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, request.hostUserId);
    ENSURE_OR_RETURN_VAL(getHostUserIdRet, std::nullopt);
    bool getExtraInfoRet = attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, request.extraInfo);
    ENSURE_OR_RETURN_VAL(getExtraInfoRet, std::nullopt);
    auto companionDeviceKeyOpt = DecodeCompanionDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(companionDeviceKeyOpt.has_value(), std::nullopt);
    request.companionDeviceKey = *companionDeviceKeyOpt;
    return request;
}

bool EncodeObtainTokenReply(const ObtainTokenReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, reply.result);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.extraInfo);
    return true;
}

std::optional<ObtainTokenReply> DecodeObtainTokenReply(const Attributes &attributes)
{
    ObtainTokenReply reply {};
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, reply.result);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);
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
