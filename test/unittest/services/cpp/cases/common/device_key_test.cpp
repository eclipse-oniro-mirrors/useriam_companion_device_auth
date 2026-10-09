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
 * Description: DeviceKey extension unit tests (deviceSubProfileId field)
 * Create: 2026
 */

#include <gtest/gtest.h>

#include "service_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class DeviceKeyExtensionTest : public testing::Test {};

constexpr int32_t INT32_100 = 100;
constexpr int32_t INT32_200 = 200;
constexpr int32_t INT32_SUB_1 = 100001;
constexpr int32_t INT32_SUB_2 = 100002;

DeviceKey MakeDeviceKey(DeviceIdType idType, const std::string &deviceId, UserId deviceUserId, int32_t subProfileId)
{
    return DeviceKey { .idType = idType,
        .deviceId = deviceId,
        .deviceUserId = deviceUserId,
        .deviceSubProfileId = subProfileId };
}

/**
 * Scenario: DeviceKey::operator== includes deviceSubProfileId in comparison
 * Expected: Keys with different subProfileId are not equal
 */
HWTEST_F(DeviceKeyExtensionTest, OperatorEqual_DifferentSubProfileId_NotEqual, TestSize.Level0)
{
    auto key1 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INT32_SUB_1);
    auto key2 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INT32_SUB_2);

    EXPECT_FALSE(key1 == key2);
    EXPECT_TRUE(key1 != key2);
}

/**
 * Scenario: DeviceKey::operator== with same subProfileId
 * Expected: Keys are equal
 */
HWTEST_F(DeviceKeyExtensionTest, OperatorEqual_SameSubProfileId_Equal, TestSize.Level0)
{
    auto key1 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INT32_SUB_1);
    auto key2 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INT32_SUB_1);

    EXPECT_TRUE(key1 == key2);
    EXPECT_FALSE(key1 != key2);
}

/**
 * Scenario: DeviceKey::operator== with INVALID_SUB_PROFILE_ID
 * Expected: Keys with same INVALID_SUB_PROFILE_ID are equal
 */
HWTEST_F(DeviceKeyExtensionTest, OperatorEqual_BothInvalidSubProfileId_Equal, TestSize.Level0)
{
    auto key1 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INVALID_SUB_PROFILE_ID);
    auto key2 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INVALID_SUB_PROFILE_ID);

    EXPECT_TRUE(key1 == key2);
}

/**
 * Scenario: DeviceKey::operator< includes deviceSubProfileId in comparison
 * Expected: Key with smaller subProfileId is less than key with larger subProfileId when other fields match
 */
HWTEST_F(DeviceKeyExtensionTest, OperatorLess_DifferentSubProfileId_CorrectOrdering, TestSize.Level0)
{
    auto key1 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INT32_SUB_1);
    auto key2 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INT32_SUB_2);

    EXPECT_TRUE(key1 < key2);
    EXPECT_FALSE(key2 < key1);
}

/**
 * Scenario: DeviceKey::operator< with different idType takes precedence over subProfileId
 * Expected: idType comparison takes priority
 */
HWTEST_F(DeviceKeyExtensionTest, OperatorLess_IdTypePrecedence, TestSize.Level0)
{
    auto key1 = MakeDeviceKey(DeviceIdType::UNKNOWN, "device_A", INT32_100, INT32_SUB_2);
    auto key2 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INT32_SUB_1);

    EXPECT_TRUE(key1 < key2);
    EXPECT_FALSE(key2 < key1);
}

/**
 * Scenario: DeviceKey::operator< with different deviceId takes precedence over subProfileId
 * Expected: deviceId comparison takes priority over subProfileId
 */
HWTEST_F(DeviceKeyExtensionTest, OperatorLess_DeviceIdPrecedence, TestSize.Level0)
{
    auto key1 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INT32_SUB_2);
    auto key2 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_B", INT32_100, INT32_SUB_1);

    EXPECT_TRUE(key1 < key2);
}

/**
 * Scenario: DeviceKey::operator< with different deviceUserId takes precedence over subProfileId
 * Expected: deviceUserId comparison takes priority over subProfileId
 */
HWTEST_F(DeviceKeyExtensionTest, OperatorLess_UserIdPrecedence, TestSize.Level0)
{
    auto key1 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INT32_SUB_2);
    auto key2 = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_200, INT32_SUB_1);

    EXPECT_TRUE(key1 < key2);
}

/**
 * Scenario: DeviceKey::GetDesc includes sub profile information
 * Expected: The description string contains the sub profile id
 */
HWTEST_F(DeviceKeyExtensionTest, GetDesc_IncludesSubProfileId, TestSize.Level0)
{
    auto key = MakeDeviceKey(DeviceIdType::UNIFIED_DEVICE_ID, "device_A", INT32_100, INT32_SUB_1);

    std::string desc = key.GetDesc();
    EXPECT_NE(desc.find("sub:"), std::string::npos);
}

/**
 * Scenario: DeviceKey default deviceSubProfileId is INVALID_SUB_PROFILE_ID
 * Expected: Default constructed key has INVALID_SUB_PROFILE_ID
 */
HWTEST_F(DeviceKeyExtensionTest, DefaultSubProfileId_IsInvalid, TestSize.Level0)
{
    DeviceKey key;
    EXPECT_EQ(key.deviceSubProfileId, INVALID_SUB_PROFILE_ID);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
