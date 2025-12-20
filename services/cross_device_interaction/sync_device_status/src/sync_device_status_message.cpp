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

#include "sync_device_status_message.h"

#include "iam_check.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

bool EncodeSyncDeviceStatusRequest(const SyncDeviceStatusRequest &request, Attributes &attributes)
{
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(request.protocolIdList));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(request.capabilityList));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, request.hostDeviceKey.deviceUserId);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_SALT, request.salt);
    attributes.SetUint64Value(Attributes::ATTR_CDA_SA_CHALLENGE, request.challenge);
    return true;
}

bool DecodeSyncDeviceStatusRequest(const Attributes &attributes, SyncDeviceStatusRequest &request)
{
    std::vector<uint16_t> protocolList;
    bool getProtocolListRet = attributes.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocolList);
    ENSURE_OR_RETURN_VAL(getProtocolListRet, false);
    std::vector<uint16_t> capabilityList;
    bool getCapabilityListRet = attributes.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, capabilityList);
    ENSURE_OR_RETURN_VAL(getCapabilityListRet, false);
    auto hostDeviceKey = DecodeHostDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(hostDeviceKey.has_value(), false);
    request.hostDeviceKey = *hostDeviceKey;
    bool getSaltRet = attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_SALT, request.salt);
    ENSURE_OR_RETURN_VAL(getSaltRet, false);
    bool getChallengeRet = attributes.GetUint64Value(Attributes::ATTR_CDA_SA_CHALLENGE, request.challenge);
    ENSURE_OR_RETURN_VAL(getChallengeRet, false);
    request.protocolIdList = ProtocolIdConverter::FromUnderlyingVec(protocolList);
    request.capabilityList = CapabilityConverter::FromUnderlyingVec(capabilityList);
    return true;
}

bool EncodeSyncDeviceStatusReply(const SyncDeviceStatusReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(reply.protocolIdList));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(reply.capabilityList));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, reply.companionDeviceKey.deviceUserId);
    attributes.SetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID,
        SecureProtocolIdConverter::ToUnderlying(reply.secureProtocolId));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, reply.deviceUserName);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.companionCheckResponse);
    return true;
}

bool DecodeSyncDeviceStatusReply(const Attributes &attributes, SyncDeviceStatusReply &reply)
{
    int32_t resultCode = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, resultCode);
    ENSURE_OR_RETURN_VAL(getResultRet, false);
    reply.result = static_cast<ResultCode>(resultCode);
    if (reply.result != ResultCode::SUCCESS) {
        return true;
    }

    std::vector<uint16_t> protocolList;
    bool getProtocolListRet = attributes.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocolList);
    ENSURE_OR_RETURN_VAL(getProtocolListRet, false);
    std::vector<uint16_t> capabilityList;
    bool getCapabilityListRet = attributes.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, capabilityList);
    ENSURE_OR_RETURN_VAL(getCapabilityListRet, false);
    auto companionDeviceKey = DecodeCompanionDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(companionDeviceKey.has_value(), false);
    reply.companionDeviceKey = *companionDeviceKey;
    uint16_t secureProtocolId = 0;
    bool getSecureProtocolIdRet =
        attributes.GetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID, secureProtocolId);
    ENSURE_OR_RETURN_VAL(getSecureProtocolIdRet, false);
    bool getUserNameRet = attributes.GetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, reply.deviceUserName);
    ENSURE_OR_RETURN_VAL(getUserNameRet, false);
    bool getExtraInfoRet =
        attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.companionCheckResponse);
    ENSURE_OR_RETURN_VAL(getExtraInfoRet, false);
    reply.protocolIdList = ProtocolIdConverter::FromUnderlyingVec(protocolList);
    reply.capabilityList = CapabilityConverter::FromUnderlyingVec(capabilityList);
    reply.secureProtocolId = SecureProtocolIdConverter::FromUnderlying(secureProtocolId);
    return true;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
