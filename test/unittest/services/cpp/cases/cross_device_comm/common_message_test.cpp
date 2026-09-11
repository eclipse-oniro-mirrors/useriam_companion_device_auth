/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

/*
 * Description: CommonMessage and IpcDeviceStatus extension unit tests (sub-profile fields)
 * Create: 2026
 */

#include <gtest/gtest.h>

#include "attributes.h"
#include "common_message.h"
#include "service_common.h"
#include "subscription_util.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_100 = 100;
constexpr int32_t INT32_200 = 200;
constexpr int32_t INT32_SUB_1 = 100001;
constexpr int32_t INT32_SUB_2 = 100002;

class CommonMessageTest : public Test {
protected:
    void SetUp() override
    {
        hostKey_ = DeviceKey { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
            .deviceId = "host_device_id",
            .deviceUserId = INT32_100,
            .deviceSubProfileId = INT32_SUB_1 };
        companionKey_ = DeviceKey { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
            .deviceId = "companion_device_id",
            .deviceUserId = INT32_200,
            .deviceSubProfileId = INT32_SUB_2 };
    }

    DeviceKey hostKey_;
    DeviceKey companionKey_;
};

/**
 * Scenario: DecodeHostDeviceKey with subProfileIdKey present
 * Expected: deviceSubProfileId is decoded from attributes
 */
HWTEST_F(CommonMessageTest, DecodeHostDeviceKey_WithSubProfileId, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_SUB_PROFILE_ID, hostKey_.deviceSubProfileId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostKey_.deviceId);

    auto result = DecodeHostDeviceKey(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->deviceSubProfileId, INT32_SUB_1);
}

/**
 * Scenario: DecodeHostDeviceKey without subProfileIdKey
 * Expected: deviceSubProfileId defaults to INVALID_SUB_PROFILE_ID
 */
HWTEST_F(CommonMessageTest, DecodeHostDeviceKey_WithoutSubProfileId_DefaultsInvalid, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostKey_.deviceUserId);
    // ATTR_CDA_SA_HOST_SUB_PROFILE_ID intentionally omitted
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostKey_.deviceId);

    auto result = DecodeHostDeviceKey(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->deviceSubProfileId, INVALID_SUB_PROFILE_ID);
}

/**
 * Scenario: DecodeCompanionDeviceKey with subProfileIdKey present
 * Expected: deviceSubProfileId is decoded from attributes
 */
HWTEST_F(CommonMessageTest, DecodeCompanionDeviceKey_WithSubProfileId, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, companionKey_.deviceSubProfileId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(companionKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, companionKey_.deviceId);

    auto result = DecodeCompanionDeviceKey(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->deviceSubProfileId, INT32_SUB_2);
}

/**
 * Scenario: DecodeCompanionDeviceKey without subProfileIdKey
 * Expected: deviceSubProfileId defaults to INVALID_SUB_PROFILE_ID
 */
HWTEST_F(CommonMessageTest, DecodeCompanionDeviceKey_WithoutSubProfileId_DefaultsInvalid, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionKey_.deviceUserId);
    // ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID intentionally omitted
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(companionKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, companionKey_.deviceId);

    auto result = DecodeCompanionDeviceKey(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->deviceSubProfileId, INVALID_SUB_PROFILE_ID);
}

/**
 * Scenario: EncodeHostDeviceKey and DecodeHostDeviceKey round-trip with subProfileId
 * Expected: Full round-trip preserves all DeviceKey fields including subProfileId
 */
HWTEST_F(CommonMessageTest, HostDeviceKey_RoundTrip_WithSubProfileId, TestSize.Level0)
{
    Attributes attributes;
    EncodeHostDeviceKey(hostKey_, attributes);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostKey_.deviceId);

    auto result = DecodeHostDeviceKey(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->idType, hostKey_.idType);
    EXPECT_EQ(result->deviceId, hostKey_.deviceId);
    EXPECT_EQ(result->deviceUserId, hostKey_.deviceUserId);
    EXPECT_EQ(result->deviceSubProfileId, hostKey_.deviceSubProfileId);
}

/**
 * Scenario: EncodeCompanionDeviceKey and DecodeCompanionDeviceKey round-trip with subProfileId
 * Expected: Full round-trip preserves all DeviceKey fields including subProfileId
 */
HWTEST_F(CommonMessageTest, CompanionDeviceKey_RoundTrip_WithSubProfileId, TestSize.Level0)
{
    Attributes attributes;
    EncodeCompanionDeviceKey(companionKey_, attributes);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(companionKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, companionKey_.deviceId);

    auto result = DecodeCompanionDeviceKey(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->idType, companionKey_.idType);
    EXPECT_EQ(result->deviceId, companionKey_.deviceId);
    EXPECT_EQ(result->deviceUserId, companionKey_.deviceUserId);
    EXPECT_EQ(result->deviceSubProfileId, companionKey_.deviceSubProfileId);
}

/**
 * Scenario: IpcDeviceStatusEqual with different deviceSubProfileId
 * Expected: Returns false
 */
HWTEST_F(CommonMessageTest, IpcDeviceStatusEqual_DifferentSubProfileId_NotEqual, TestSize.Level0)
{
    IpcDeviceStatus lhs = {};
    lhs.deviceKey.deviceIdType = 1;
    lhs.deviceKey.deviceId = "device_A";
    lhs.deviceKey.deviceUserId = INT32_100;
    lhs.deviceKey.deviceSubProfileId = INT32_SUB_1;
    lhs.deviceUserName = "user";
    lhs.deviceModelInfo = "model";
    lhs.deviceName = "name";
    lhs.isOnline = true;
    lhs.deviceSubProfileName = "Sub1";

    IpcDeviceStatus rhs = lhs;
    rhs.deviceKey.deviceSubProfileId = INT32_SUB_2;

    EXPECT_FALSE(IpcDeviceStatusEqual(lhs, rhs));
}

/**
 * Scenario: IpcDeviceStatusEqual with different deviceSubProfileName
 * Expected: Returns false
 */
HWTEST_F(CommonMessageTest, IpcDeviceStatusEqual_DifferentSubProfileName_NotEqual, TestSize.Level0)
{
    IpcDeviceStatus lhs = {};
    lhs.deviceKey.deviceIdType = 1;
    lhs.deviceKey.deviceId = "device_A";
    lhs.deviceKey.deviceUserId = INT32_100;
    lhs.deviceKey.deviceSubProfileId = INT32_SUB_1;
    lhs.deviceUserName = "user";
    lhs.deviceModelInfo = "model";
    lhs.deviceName = "name";
    lhs.isOnline = true;
    lhs.deviceSubProfileName = "Sub1";

    IpcDeviceStatus rhs = lhs;
    rhs.deviceSubProfileName = "Sub2";

    EXPECT_FALSE(IpcDeviceStatusEqual(lhs, rhs));
}

/**
 * Scenario: IpcDeviceStatusEqual with identical sub-profile fields
 * Expected: Returns true
 */
HWTEST_F(CommonMessageTest, IpcDeviceStatusEqual_SameSubProfileFields_Equal, TestSize.Level0)
{
    IpcDeviceStatus lhs = {};
    lhs.deviceKey.deviceIdType = 1;
    lhs.deviceKey.deviceId = "device_A";
    lhs.deviceKey.deviceUserId = INT32_100;
    lhs.deviceKey.deviceSubProfileId = INT32_SUB_1;
    lhs.deviceUserName = "user";
    lhs.deviceModelInfo = "model";
    lhs.deviceName = "name";
    lhs.isOnline = true;
    lhs.deviceSubProfileName = "Sub1";

    IpcDeviceStatus rhs = lhs;

    EXPECT_TRUE(IpcDeviceStatusEqual(lhs, rhs));
}

/**
 * Scenario: IpcDeviceStatusVectorEqual with sub-profile differences
 * Expected: Vectors differ when sub-profile fields differ
 */
HWTEST_F(CommonMessageTest, IpcDeviceStatusVectorEqual_DifferentSubProfile, TestSize.Level0)
{
    IpcDeviceStatus status1 = {};
    status1.deviceKey.deviceIdType = 1;
    status1.deviceKey.deviceId = "device_A";
    status1.deviceKey.deviceUserId = INT32_100;
    status1.deviceKey.deviceSubProfileId = INT32_SUB_1;
    status1.deviceSubProfileName = "Sub1";

    IpcDeviceStatus status2 = status1;
    status2.deviceKey.deviceSubProfileId = INT32_SUB_2;
    status2.deviceSubProfileName = "Sub2";

    std::vector<IpcDeviceStatus> vec1 = { status1 };
    std::vector<IpcDeviceStatus> vec2 = { status2 };

    EXPECT_FALSE(IpcDeviceStatusVectorEqual(vec1, vec2));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
