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

#include <optional>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_SYNC_DEVICE_STATUS_MESSAGE

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

void EncodeSyncDeviceStatusRequest(const SyncDeviceStatusRequest &request, Attributes &attributes)
{
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(request.hostProtocolIdList));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(request.hostCapabilityList));
    EncodeHostDeviceKey(request.hostDeviceKey, attributes);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_SALT, request.salt);
    attributes.SetUint64Value(Attributes::ATTR_CDA_SA_CHALLENGE, request.challenge);
}

std::optional<SyncDeviceStatusRequest> DecodeSyncDeviceStatusRequest(const Attributes &attributes)
{
    std::vector<uint16_t> hostProtocolIdList;
    bool getProtocolListRet =
        attributes.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, hostProtocolIdList);
    ENSURE_OR_RETURN_VAL(getProtocolListRet, std::nullopt);
    std::vector<uint16_t> hostCapabilityList;
    bool getCapabilityListRet =
        attributes.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, hostCapabilityList);
    ENSURE_OR_RETURN_VAL(getCapabilityListRet, std::nullopt);
    auto hostDeviceKey = DecodeHostDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(hostDeviceKey.has_value(), std::nullopt);

    SyncDeviceStatusRequest request {};
    request.hostDeviceKey = *hostDeviceKey;
    bool getSaltRet = attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_SALT, request.salt);
    ENSURE_OR_RETURN_VAL(getSaltRet, std::nullopt);
    bool getChallengeRet = attributes.GetUint64Value(Attributes::ATTR_CDA_SA_CHALLENGE, request.challenge);
    ENSURE_OR_RETURN_VAL(getChallengeRet, std::nullopt);
    request.hostProtocolIdList = ProtocolIdConverter::FromUnderlyingVec(hostProtocolIdList);
    request.hostCapabilityList = CapabilityConverter::FromUnderlyingVec(hostCapabilityList);
    if (HasBindingSignatureAttributes(attributes)) {
        auto bindingSignatureProofOpt = DecodeBindingSignatureAttributes(attributes);
        ENSURE_OR_RETURN_VAL(bindingSignatureProofOpt.has_value(), std::nullopt);
        request.bindingSignatureProof = *bindingSignatureProofOpt;
    }
    if (HasCompanionUserKey(attributes)) {
        auto companionUserKeyOpt = DecodeCompanionUserKey(attributes);
        ENSURE_OR_RETURN_VAL(companionUserKeyOpt.has_value(), std::nullopt);
        request.companionUserKey = *companionUserKeyOpt;
    }
    return request;
}

void EncodeSyncDeviceStatusReply(const SyncDeviceStatusReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(reply.companionProofProtocolIdList));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(reply.companionCapabilityList));
    attributes.SetInt32ArrayValue(Attributes::ATTR_CDA_SA_BUSINESS_ID_LIST,
        BusinessIdConverter::ToUnderlyingVec(reply.businessIdList));
    EncodeCompanionDeviceKey(reply.companionDeviceKey, attributes);
    attributes.SetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID,
        SecureProtocolIdConverter::ToUnderlying(reply.secureProtocolId));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, reply.deviceUserName);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_DEVICE_NAME, reply.deviceName);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.companionCheckResponse);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_DEVICE_SUB_PROFILE_NAME, reply.deviceSubProfileName);
    if (reply.maxAuthTrustLevel.has_value()) {
        attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_MAX_ATL, reply.maxAuthTrustLevel.value());
    }
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_COMPANION_SUPPORTED_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(reply.companionSupportedProtocolIdList));
}

namespace {
bool DecodeCompanionMaxAtl(const Attributes &attributes, std::optional<int32_t> &maxAuthTrustLevel)
{
    maxAuthTrustLevel.reset();
    if (!attributes.HasAttribute(Attributes::ATTR_CDA_SA_COMPANION_MAX_ATL)) {
        return true;
    }
    int32_t value = 0;
    bool getMaxAtlRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_MAX_ATL, value);
    ENSURE_OR_RETURN_VAL(getMaxAtlRet, false);
    ENSURE_OR_RETURN_VAL(IsValidAtl(value), false);
    maxAuthTrustLevel = value;
    return true;
}

bool DecodeSyncDeviceStatusReplySuccessFields(const Attributes &attributes, SyncDeviceStatusReply &reply)
{
    std::vector<uint16_t> companionProofProtocolList;
    bool getProtocolListRet =
        attributes.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, companionProofProtocolList);
    ENSURE_OR_RETURN_VAL(getProtocolListRet, false);
    std::vector<uint16_t> companionCapabilityList;
    bool getCapabilityListRet =
        attributes.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, companionCapabilityList);
    ENSURE_OR_RETURN_VAL(getCapabilityListRet, false);
    std::vector<int32_t> businessIdList;
    if (attributes.HasAttribute(Attributes::ATTR_CDA_SA_BUSINESS_ID_LIST)) {
        bool getBusinessIdListRet =
            attributes.GetInt32ArrayValue(Attributes::ATTR_CDA_SA_BUSINESS_ID_LIST, businessIdList);
        ENSURE_OR_RETURN_VAL(getBusinessIdListRet, false);
    }
    auto companionDeviceKey = DecodeCompanionDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(companionDeviceKey.has_value(), false);
    reply.companionDeviceKey = *companionDeviceKey;
    uint16_t secureProtocolId = 0;
    bool getSecureProtocolIdRet =
        attributes.GetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID, secureProtocolId);
    ENSURE_OR_RETURN_VAL(getSecureProtocolIdRet, false);
    bool getUserNameRet = attributes.GetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, reply.deviceUserName);
    ENSURE_OR_RETURN_VAL(getUserNameRet, false);
    if (attributes.HasAttribute(Attributes::ATTR_CDA_SA_DEVICE_NAME)) {
        attributes.GetStringValue(Attributes::ATTR_CDA_SA_DEVICE_NAME, reply.deviceName);
    }
    if (attributes.HasAttribute(Attributes::ATTR_CDA_SA_DEVICE_SUB_PROFILE_NAME)) {
        attributes.GetStringValue(Attributes::ATTR_CDA_SA_DEVICE_SUB_PROFILE_NAME, reply.deviceSubProfileName);
    }
    std::optional<int32_t> maxAuthTrustLevel;
    ENSURE_OR_RETURN_VAL(DecodeCompanionMaxAtl(attributes, maxAuthTrustLevel), false);
    reply.maxAuthTrustLevel = maxAuthTrustLevel;
    bool getExtraInfoRet =
        attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.companionCheckResponse);
    ENSURE_OR_RETURN_VAL(getExtraInfoRet, false);
    reply.companionProofProtocolIdList = ProtocolIdConverter::FromUnderlyingVec(companionProofProtocolList);
    reply.companionSupportedProtocolIdList = reply.companionProofProtocolIdList;
    if (attributes.HasAttribute(Attributes::ATTR_CDA_SA_COMPANION_SUPPORTED_PROTOCOL_ID_LIST)) {
        std::vector<uint16_t> supportedProtocolList;
        bool getSupportedRet = attributes.GetUint16ArrayValue(
            Attributes::ATTR_CDA_SA_COMPANION_SUPPORTED_PROTOCOL_ID_LIST, supportedProtocolList);
        ENSURE_OR_RETURN_VAL(getSupportedRet, false);
        reply.companionSupportedProtocolIdList = ProtocolIdConverter::FromUnderlyingVec(supportedProtocolList);
    }
    reply.companionCapabilityList = CapabilityConverter::FromUnderlyingVec(companionCapabilityList);
    reply.businessIdList = BusinessIdConverter::FromUnderlyingVec(businessIdList);
    reply.secureProtocolId = SecureProtocolIdConverter::FromUnderlying(secureProtocolId);
    return true;
}
} // namespace

std::optional<SyncDeviceStatusReply> DecodeSyncDeviceStatusReply(const Attributes &attributes)
{
    int32_t resultCode = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, resultCode);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);

    SyncDeviceStatusReply reply {};
    reply.result = static_cast<ResultCode>(resultCode);
    if (HasCompanionUserKey(attributes)) {
        auto companionUserKeyOpt = DecodeCompanionUserKey(attributes);
        ENSURE_OR_RETURN_VAL(companionUserKeyOpt.has_value(), std::nullopt);
        reply.companionUserKey = *companionUserKeyOpt;
    }
    if (reply.result != ResultCode::SUCCESS) {
        return reply;
    }

    ENSURE_OR_RETURN_VAL(DecodeSyncDeviceStatusReplySuccessFields(attributes, reply), std::nullopt);
    return reply;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
