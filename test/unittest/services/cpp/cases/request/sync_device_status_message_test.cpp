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
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }

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
    SyncDeviceStatusRequest request = { .protocolIdList = protocolIdList_,
        .capabilityList = capabilityList_,
        .hostDeviceKey = hostDeviceKey_,
        .salt = salt_,
        .challenge = challenge_ };

    Attributes attributes;
    bool encodeResult = EncodeSyncDeviceStatusRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusRequest decoded = result.value();

    EXPECT_EQ(decoded.protocolIdList, request.protocolIdList);
    EXPECT_EQ(decoded.capabilityList, request.capabilityList);
    EXPECT_EQ(decoded.hostDeviceKey.idType, request.hostDeviceKey.idType);
    EXPECT_EQ(decoded.hostDeviceKey.deviceId, request.hostDeviceKey.deviceId);
    EXPECT_EQ(decoded.hostDeviceKey.deviceUserId, request.hostDeviceKey.deviceUserId);
    EXPECT_EQ(decoded.salt, request.salt);
    EXPECT_EQ(decoded.challenge, request.challenge);
}

HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusRequest_002, TestSize.Level0)
{
    SyncDeviceStatusRequest request = { .protocolIdList = {},
        .capabilityList = {},
        .hostDeviceKey = hostDeviceKey_,
        .salt = {},
        .challenge = 0 };

    Attributes attributes;
    bool encodeResult = EncodeSyncDeviceStatusRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusRequest(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusRequest decoded = result.value();

    EXPECT_TRUE(decoded.protocolIdList.empty());
    EXPECT_TRUE(decoded.capabilityList.empty());
    EXPECT_TRUE(decoded.salt.empty());
    EXPECT_EQ(decoded.challenge, 0);
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

HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusReply_001, TestSize.Level0)
{
    SyncDeviceStatusReply reply = { .result = ResultCode::SUCCESS,
        .protocolIdList = protocolIdList_,
        .capabilityList = capabilityList_,
        .secureProtocolId = secureProtocolId_,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = deviceUserName_,
        .companionCheckResponse = companionCheckResponse_ };

    Attributes attributes;
    bool encodeResult = EncodeSyncDeviceStatusReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(reply.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, reply.companionDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusReply decoded = result.value();

    EXPECT_EQ(decoded.result, reply.result);
    EXPECT_EQ(decoded.protocolIdList, reply.protocolIdList);
    EXPECT_EQ(decoded.capabilityList, reply.capabilityList);
    EXPECT_EQ(decoded.secureProtocolId, reply.secureProtocolId);
    EXPECT_EQ(decoded.companionDeviceKey.idType, reply.companionDeviceKey.idType);
    EXPECT_EQ(decoded.companionDeviceKey.deviceId, reply.companionDeviceKey.deviceId);
    EXPECT_EQ(decoded.companionDeviceKey.deviceUserId, reply.companionDeviceKey.deviceUserId);
    EXPECT_EQ(decoded.deviceUserName, reply.deviceUserName);
    EXPECT_EQ(decoded.companionCheckResponse, reply.companionCheckResponse);
}

HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusReply_002, TestSize.Level0)
{
    SyncDeviceStatusReply reply = { .result = ResultCode::GENERAL_ERROR,
        .protocolIdList = protocolIdList_,
        .capabilityList = capabilityList_,
        .secureProtocolId = secureProtocolId_,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = deviceUserName_,
        .companionCheckResponse = companionCheckResponse_ };

    Attributes attributes;
    bool encodeResult = EncodeSyncDeviceStatusReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusReply decoded = result.value();

    EXPECT_EQ(decoded.result, reply.result);
}

HWTEST_F(SyncDeviceStatusMessageTest, EncodeSyncDeviceStatusReply_003, TestSize.Level0)
{
    SyncDeviceStatusReply reply = { .result = ResultCode::SUCCESS,
        .protocolIdList = {},
        .capabilityList = {},
        .secureProtocolId = SecureProtocolId::INVALID,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = "",
        .companionCheckResponse = {} };

    Attributes attributes;
    bool encodeResult = EncodeSyncDeviceStatusReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(reply.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, reply.companionDeviceKey.deviceId);

    auto result = DecodeSyncDeviceStatusReply(attributes);
    ASSERT_TRUE(result.has_value());
    SyncDeviceStatusReply decoded = result.value();

    EXPECT_EQ(decoded.result, reply.result);
    EXPECT_TRUE(decoded.protocolIdList.empty());
    EXPECT_TRUE(decoded.capabilityList.empty());
    EXPECT_EQ(decoded.secureProtocolId, SecureProtocolId::INVALID);
    EXPECT_TRUE(decoded.deviceUserName.empty());
    EXPECT_TRUE(decoded.companionCheckResponse.empty());
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

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
