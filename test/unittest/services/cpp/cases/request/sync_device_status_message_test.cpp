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

#include <gtest/gtest.h>

#include "attributes.h"
#include "common_message.h"
#include "sync_device_status_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class SyncDeviceStatusMessageTest : public Test {
public:
protected:
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
    std::vector<ProtocolId> protocolIdList_ = { ProtocolId::VERSION_1 };
    std::vector<Capability> capabilityList_ = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH };
    std::vector<uint8_t> salt_ = { 1, 2, 3, 4, 5 };
    std::vector<uint8_t> companionCheckResponse_ = { 6, 7, 8, 9, 10 };
    uint64_t challenge_ = 123456789;
    std::string deviceUserName_ = "test_user";
    SecureProtocolId secureProtocolId_ = SecureProtocolId::DEFAULT;
};

HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusRequest_001, TestSize.Level0)
{
    SyncDeviceStatusRequest request = { .hostProtocolIdList = protocolIdList_,
        .hostCapabilityList = capabilityList_,
        .hostDeviceKey = hostDeviceKey_,
        .salt = salt_,
        .challenge = challenge_ };

    Attributes attributes;
    EncodeSyncDeviceStatusRequest(request, attributes);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusRequest decoded = result.value();

    EXPECT_EQ(decoded.hostProtocolIdList, request.hostProtocolIdList);
    EXPECT_EQ(decoded.hostCapabilityList, request.hostCapabilityList);
    EXPECT_EQ(decoded.hostDeviceKey.idType, request.hostDeviceKey.idType);
    EXPECT_EQ(decoded.hostDeviceKey.deviceId, request.hostDeviceKey.deviceId);
    EXPECT_EQ(decoded.hostDeviceKey.deviceUserId, request.hostDeviceKey.deviceUserId);
    EXPECT_EQ(decoded.salt, request.salt);
    EXPECT_EQ(decoded.challenge, request.challenge);
}

HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusRequest_002, TestSize.Level0)
{
    SyncDeviceStatusRequest request = { .hostProtocolIdList = {},
        .hostCapabilityList = {},
        .hostDeviceKey = hostDeviceKey_,
        .salt = {},
        .challenge = 0 };

    Attributes attributes;
    EncodeSyncDeviceStatusRequest(request, attributes);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusRequest decoded = result.value();

    EXPECT_TRUE(decoded.hostProtocolIdList.empty());
    EXPECT_TRUE(decoded.hostCapabilityList.empty());
    EXPECT_TRUE(decoded.salt.empty());
    EXPECT_EQ(decoded.challenge, 0);
}

HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusRequest_WithBindingSignature, TestSize.Level0)
{
    SyncDeviceStatusRequest request = { .hostProtocolIdList = protocolIdList_,
        .hostCapabilityList = capabilityList_,
        .hostDeviceKey = hostDeviceKey_,
        .salt = salt_,
        .challenge = challenge_ };

    Attributes attributes;
    EncodeSyncDeviceStatusRequest(request, attributes);
    std::vector<uint8_t> bindingChallenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
    std::vector<uint8_t> bindingSignature = { 0xCD, 0xEF };
    AttachBindingSignatureAttributes(bindingChallenge, bindingSignature, attributes);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->bindingSignatureProof.has_value());
    EXPECT_EQ(result->bindingSignatureProof->challenge, bindingChallenge);
    EXPECT_EQ(result->bindingSignatureProof->signature, bindingSignature);
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusRequest_001, TestSize.Level0)
{
    Attributes attributes;

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusRequest_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusRequest_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(capabilityList_));

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusRequest_004, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(capabilityList_));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusRequest_005, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(capabilityList_));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_SALT, salt_);

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    EXPECT_FALSE(result.has_value());
}

// Legacy-format request without the asserted peer identity decodes with the field absent
// (unsigned discovery/V1 rounds never carry it).
HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusRequest_WithoutCompanionUserKey_OldFormat, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(capabilityList_));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_SALT, salt_);
    attributes.SetUint64Value(Attributes::ATTR_CDA_SA_CHALLENGE, challenge_);

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->companionUserKey.has_value());
}

// Signed rounds assert the peer identity via the companion user key attributes.
HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusRequest_WithCompanionUserKey, TestSize.Level0)
{
    const UserKey companionUserKey = { 200, 1 };
    Attributes attributes;
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(capabilityList_));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_SALT, salt_);
    attributes.SetUint64Value(Attributes::ATTR_CDA_SA_CHALLENGE, challenge_);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionUserKey.userId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, companionUserKey.subProfileId);

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->companionUserKey.has_value());
    EXPECT_EQ(*result->companionUserKey, companionUserKey);
}

HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusReply_001, TestSize.Level0)
{
    SyncDeviceStatusReply reply = { .result = ResultCode::SUCCESS,
        .companionProtocolIdList = protocolIdList_,
        .companionCapabilityList = capabilityList_,
        .secureProtocolId = secureProtocolId_,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = deviceUserName_,
        .deviceName = "test_device_name",
        .companionCheckResponse = companionCheckResponse_,
        .deviceSubProfileName = "test_sub_profile" };

    Attributes attributes;
    EncodeSyncDeviceStatusReply(reply, attributes);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(reply.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, reply.companionDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusReply decoded = result.value();

    EXPECT_EQ(decoded.result, reply.result);
    EXPECT_EQ(decoded.companionProtocolIdList, reply.companionProtocolIdList);
    EXPECT_EQ(decoded.companionCapabilityList, reply.companionCapabilityList);
    EXPECT_EQ(decoded.secureProtocolId, reply.secureProtocolId);
    EXPECT_EQ(decoded.companionDeviceKey.idType, reply.companionDeviceKey.idType);
    EXPECT_EQ(decoded.companionDeviceKey.deviceId, reply.companionDeviceKey.deviceId);
    EXPECT_EQ(decoded.companionDeviceKey.deviceUserId, reply.companionDeviceKey.deviceUserId);
    EXPECT_EQ(decoded.deviceUserName, reply.deviceUserName);
    EXPECT_EQ(decoded.deviceName, reply.deviceName);
    EXPECT_EQ(decoded.companionCheckResponse, reply.companionCheckResponse);
    EXPECT_EQ(decoded.deviceSubProfileName, reply.deviceSubProfileName);
}

HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusReply_002, TestSize.Level0)
{
    SyncDeviceStatusReply reply = { .result = ResultCode::GENERAL_ERROR,
        .companionProtocolIdList = protocolIdList_,
        .companionCapabilityList = capabilityList_,
        .secureProtocolId = secureProtocolId_,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = deviceUserName_,
        .companionCheckResponse = companionCheckResponse_ };

    Attributes attributes;
    EncodeSyncDeviceStatusReply(reply, attributes);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusReply decoded = result.value();

    EXPECT_EQ(decoded.result, reply.result);
}

// Old-format error reply (peer sends no identity attributes) decodes with the field absent:
// the host falls back to the round's authenticated identity.
HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_ErrorWithoutCompanionUserKey_OldFormat,
    TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::NOT_ENROLLED));

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->result, ResultCode::NOT_ENROLLED);
    EXPECT_FALSE(result->companionUserKey.has_value());
}

// Refusal replies name the peer's current user; the identity decodes on error results too.
HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_ErrorWithCompanionUserKey, TestSize.Level0)
{
    const UserKey companionUserKey = { 200, 1 };
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::NOT_ENROLLED));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionUserKey.userId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, companionUserKey.subProfileId);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->result, ResultCode::NOT_ENROLLED);
    ASSERT_TRUE(result->companionUserKey.has_value());
    EXPECT_EQ(result->companionUserKey->userId, companionUserKey.userId);
    EXPECT_EQ(result->companionUserKey->subProfileId, companionUserKey.subProfileId);
}

HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusReply_003, TestSize.Level0)
{
    SyncDeviceStatusReply reply = { .result = ResultCode::SUCCESS,
        .companionProtocolIdList = {},
        .companionCapabilityList = {},
        .secureProtocolId = SecureProtocolId::DEFAULT,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = "",
        .companionCheckResponse = {} };

    Attributes attributes;
    EncodeSyncDeviceStatusReply(reply, attributes);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(reply.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, reply.companionDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusReply decoded = result.value();

    EXPECT_EQ(decoded.result, reply.result);
    EXPECT_TRUE(decoded.companionProtocolIdList.empty());
    EXPECT_TRUE(decoded.companionCapabilityList.empty());
    EXPECT_EQ(decoded.secureProtocolId, SecureProtocolId::DEFAULT);
    EXPECT_TRUE(decoded.deviceUserName.empty());
    EXPECT_TRUE(decoded.companionCheckResponse.empty());
    EXPECT_FALSE(decoded.maxAuthTrustLevel.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusReply_CarriesMaxAuthTrustLevel, TestSize.Level0)
{
    SyncDeviceStatusReply reply = { .result = ResultCode::SUCCESS,
        .companionProtocolIdList = protocolIdList_,
        .companionCapabilityList = capabilityList_,
        .secureProtocolId = secureProtocolId_,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = deviceUserName_,
        .companionCheckResponse = companionCheckResponse_,
        .maxAuthTrustLevel = ATL3 };

    Attributes attributes;
    EncodeSyncDeviceStatusReply(reply, attributes);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(reply.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, reply.companionDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusReply decoded = result.value();

    ASSERT_TRUE(decoded.maxAuthTrustLevel.has_value());
    EXPECT_EQ(decoded.maxAuthTrustLevel.value(), ATL3);
}

// Old-format reply (peer does not send ATTR_CDA_SA_COMPANION_MAX_ATL) must decode successfully with the
// field absent, and a nullopt encode must not put the key on the wire.
HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_WithoutMaxAuthTrustLevel_OldFormat, TestSize.Level0)
{
    SyncDeviceStatusReply reply = { .result = ResultCode::SUCCESS,
        .companionProtocolIdList = protocolIdList_,
        .companionCapabilityList = capabilityList_,
        .secureProtocolId = secureProtocolId_,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = deviceUserName_,
        .companionCheckResponse = companionCheckResponse_ };

    Attributes attributes;
    EncodeSyncDeviceStatusReply(reply, attributes);

    EXPECT_FALSE(attributes.HasAttribute(Attributes::ATTR_CDA_SA_COMPANION_MAX_ATL));

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(reply.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, reply.companionDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->maxAuthTrustLevel.has_value());
}

// A carried-but-invalid maxAtl marks the whole reply invalid (same as a missing USER_NAME).
HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_InvalidMaxAuthTrustLevelFailsDecode, TestSize.Level0)
{
    SyncDeviceStatusReply reply = { .result = ResultCode::SUCCESS,
        .companionProtocolIdList = protocolIdList_,
        .companionCapabilityList = capabilityList_,
        .secureProtocolId = secureProtocolId_,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = deviceUserName_,
        .companionCheckResponse = companionCheckResponse_ };

    Attributes attributes;
    EncodeSyncDeviceStatusReply(reply, attributes);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_MAX_ATL, 12345); // not a legal ATL

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(reply.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, reply.companionDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    EXPECT_FALSE(result.has_value());
}

// Decode enforces only the field's presence; consumption is judged in the Rust security layer,
// so non-DEFAULT raw values must round-trip unchanged on their way there.
HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_PreservesFutureSecureProtocolValue, TestSize.Level0)
{
    for (auto rawSecureProtocolId : std::vector<uint16_t> { static_cast<uint16_t>(SecureProtocolId::INVALID),
             static_cast<uint16_t>(SecureProtocolId::DEFAULT) + 1 }) {
        SyncDeviceStatusReply reply = { .result = ResultCode::SUCCESS,
            .companionProtocolIdList = protocolIdList_,
            .companionCapabilityList = capabilityList_,
            .secureProtocolId = static_cast<SecureProtocolId>(rawSecureProtocolId),
            .companionDeviceKey = companionDeviceKey_,
            .deviceUserName = deviceUserName_,
            .companionCheckResponse = companionCheckResponse_ };
        Attributes attributes;
        EncodeSyncDeviceStatusReply(reply, attributes);
        attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
            static_cast<int32_t>(reply.companionDeviceKey.idType));
        attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, reply.companionDeviceKey.deviceId);
        auto result = DecodeSyncDeviceStatusReply(attributes);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->secureProtocolId, static_cast<SecureProtocolId>(rawSecureProtocolId));
    }
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_001, TestSize.Level0)
{
    Attributes attributes;

    auto result = DecodeSyncDeviceStatusReply(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));

    auto result = DecodeSyncDeviceStatusReply(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));

    auto result = DecodeSyncDeviceStatusReply(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_004, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(capabilityList_));

    auto result = DecodeSyncDeviceStatusReply(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_005, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(capabilityList_));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(companionDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, companionDeviceKey_.deviceId);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_006, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(capabilityList_));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(companionDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, companionDeviceKey_.deviceId);
    attributes.SetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID,
        SecureProtocolIdConverter::ToUnderlying(secureProtocolId_));

    auto result = DecodeSyncDeviceStatusReply(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_007, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(capabilityList_));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(companionDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, companionDeviceKey_.deviceId);
    attributes.SetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID,
        SecureProtocolIdConverter::ToUnderlying(secureProtocolId_));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, deviceUserName_);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_MissingDeviceName_DefaultsEmpty, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(capabilityList_));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(companionDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, companionDeviceKey_.deviceId);
    attributes.SetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID,
        SecureProtocolIdConverter::ToUnderlying(secureProtocolId_));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, deviceUserName_);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, companionCheckResponse_);
    // ATTR_CDA_SA_DEVICE_NAME intentionally omitted, emulating an old peer that never sends it.

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusReply decoded = result.value();

    EXPECT_TRUE(decoded.deviceName.empty());
}

/**
 * Scenario: EncodeSyncDeviceStatusReply with deviceSubProfileName
 * Expected: Round-trip encode/decode preserves this field
 */
HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusReply_WithSubProfileFields, TestSize.Level0)
{
    SyncDeviceStatusReply reply = { .result = ResultCode::SUCCESS,
        .companionProtocolIdList = protocolIdList_,
        .companionCapabilityList = capabilityList_,
        .secureProtocolId = secureProtocolId_,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = deviceUserName_,
        .deviceName = "test_device_name",
        .companionCheckResponse = companionCheckResponse_,
        .deviceSubProfileName = "SubProfile1" };

    Attributes attributes;
    EncodeSyncDeviceStatusReply(reply, attributes);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(reply.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, reply.companionDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusReply decoded = result.value();

    EXPECT_EQ(decoded.deviceSubProfileName, "SubProfile1");
}

/**
 * Scenario: DecodeSyncDeviceStatusReply without deviceSubProfileName
 * Expected: Field defaults to empty string
 */
HWTEST_F(SyncDeviceStatusMessageTest, DecodeSyncDeviceStatusReply_MissingSubProfileFields_Defaults, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST,
        ProtocolIdConverter::ToUnderlyingVec(protocolIdList_));
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        CapabilityConverter::ToUnderlyingVec(capabilityList_));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(companionDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, companionDeviceKey_.deviceId);
    attributes.SetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID,
        SecureProtocolIdConverter::ToUnderlying(secureProtocolId_));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, deviceUserName_);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_DEVICE_NAME, "test_device_name");
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, companionCheckResponse_);
    // ATTR_CDA_SA_DEVICE_SUB_PROFILE_NAME intentionally omitted

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusReply decoded = result.value();

    EXPECT_TRUE(decoded.deviceSubProfileName.empty());
}

/**
 * Scenario: EncodeSyncDeviceStatusRequest with hostDeviceKey containing deviceSubProfileId
 * Expected: Round-trip preserves deviceSubProfileId
 */
HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusRequest_WithSubProfileId, TestSize.Level0)
{
    DeviceKey hostKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100,
        .deviceSubProfileId = 100001 };

    SyncDeviceStatusRequest request = { .hostProtocolIdList = protocolIdList_,
        .hostCapabilityList = capabilityList_,
        .hostDeviceKey = hostKey,
        .salt = salt_,
        .challenge = 0 };

    Attributes attributes;
    EncodeSyncDeviceStatusRequest(request, attributes);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusRequest decoded = result.value();

    EXPECT_EQ(decoded.hostDeviceKey.deviceSubProfileId, 100001);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
