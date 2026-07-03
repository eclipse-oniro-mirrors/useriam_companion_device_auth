/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "device_status_entry.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr int32_t INT32_100 = 100;
}

class DeviceStatusEntryTest : public Test {
public:
    void SetUp() override
    {
        physicalStatus_.physicalDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        physicalStatus_.physicalDeviceKey.deviceId = "test-device-id";
        physicalStatus_.channelId = ChannelId::SOFTBUS;
        physicalStatus_.deviceModelInfo = "TestModel";
        physicalStatus_.deviceName = "TestDevice";
        physicalStatus_.isAuthMaintainActive = true;
    }

    void TearDown() override
    {
    }

protected:
    PhysicalDeviceStatus physicalStatus_;
};

HWTEST_F(DeviceStatusEntryTest, Constructor_001, TestSize.Level0)
{
    DeviceStatusEntry entry(physicalStatus_, []() {});

    EXPECT_EQ(entry.physicalDeviceKey.idType, DeviceIdType::UNIFIED_DEVICE_ID);
    EXPECT_EQ(entry.physicalDeviceKey.deviceId, "test-device-id");
    EXPECT_EQ(entry.channelId, ChannelId::SOFTBUS);
    EXPECT_EQ(entry.deviceModelInfo, "TestModel");
    EXPECT_EQ(entry.deviceName, "TestDevice");
    EXPECT_TRUE(entry.isAuthMaintainActive);
    EXPECT_FALSE(entry.isSynced);
    EXPECT_FALSE(entry.isSyncInProgress);
}

HWTEST_F(DeviceStatusEntryTest, BuildDeviceKey_001, TestSize.Level0)
{
    DeviceStatusEntry entry(physicalStatus_, []() {});

    entry.deviceUserId = INT32_100;
    DeviceKey deviceKey = entry.BuildDeviceKey();

    EXPECT_EQ(deviceKey.idType, DeviceIdType::UNIFIED_DEVICE_ID);
    EXPECT_EQ(deviceKey.deviceId, "test-device-id");
    EXPECT_EQ(deviceKey.deviceUserId, INT32_100);
}

HWTEST_F(DeviceStatusEntryTest, BuildDeviceStatus_001, TestSize.Level0)
{
    std::vector<BusinessId> hostBusinessIds = { static_cast<BusinessId>(1), static_cast<BusinessId>(2),
        static_cast<BusinessId>(3) };
    DeviceStatusEntry entry(physicalStatus_, []() {}, hostBusinessIds);

    entry.protocolId = ProtocolId::VERSION_1;
    entry.secureProtocolId = SecureProtocolId::DEFAULT;
    entry.capabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };
    entry.SetSyncCompanionBusinessIds(hostBusinessIds);
    entry.isSynced = true;

    entry.deviceUserId = INT32_100;
    DeviceStatus status = entry.BuildDeviceStatus();

    EXPECT_EQ(status.deviceKey.idType, DeviceIdType::UNIFIED_DEVICE_ID);
    EXPECT_EQ(status.deviceKey.deviceId, "test-device-id");
    EXPECT_EQ(status.deviceKey.deviceUserId, INT32_100);
    EXPECT_EQ(status.channelId, ChannelId::SOFTBUS);
    EXPECT_EQ(status.deviceName, "TestDevice");
    EXPECT_EQ(status.deviceModelInfo, "TestModel");
    EXPECT_EQ(status.protocolId, ProtocolId::VERSION_1);
    EXPECT_EQ(status.secureProtocolId, SecureProtocolId::DEFAULT);
    EXPECT_EQ(status.capabilities.size(), 2u);
    EXPECT_EQ(status.supportedBusinessIds.size(), 3u);
    EXPECT_TRUE(status.isOnline);
    EXPECT_TRUE(status.isAuthMaintainActive);
}

HWTEST_F(DeviceStatusEntryTest, Constructor_PropagatesRefreshToken_True, TestSize.Level0)
{
    physicalStatus_.refreshToken = true;
    DeviceStatusEntry entry(physicalStatus_, []() {});

    EXPECT_TRUE(entry.refreshToken);
}

HWTEST_F(DeviceStatusEntryTest, Constructor_PropagatesRefreshToken_False, TestSize.Level0)
{
    physicalStatus_.refreshToken = false;
    DeviceStatusEntry entry(physicalStatus_, []() {});

    EXPECT_FALSE(entry.refreshToken);
}

HWTEST_F(DeviceStatusEntryTest, MoveConstructor_PreservesRefreshToken_True, TestSize.Level0)
{
    physicalStatus_.refreshToken = true;
    DeviceStatusEntry entry(physicalStatus_, []() {});

    DeviceStatusEntry movedEntry(std::move(entry));

    EXPECT_TRUE(movedEntry.refreshToken);
}

HWTEST_F(DeviceStatusEntryTest, MoveConstructor_PreservesRefreshToken_False, TestSize.Level0)
{
    physicalStatus_.refreshToken = false;
    DeviceStatusEntry entry(physicalStatus_, []() {});

    DeviceStatusEntry movedEntry(std::move(entry));

    EXPECT_FALSE(movedEntry.refreshToken);
}

HWTEST_F(DeviceStatusEntryTest, BuildDeviceStatus_IncludesRefreshToken, TestSize.Level0)
{
    physicalStatus_.refreshToken = true;
    DeviceStatusEntry entry(physicalStatus_, []() {});
    entry.isSynced = true;

    DeviceStatus status = entry.BuildDeviceStatus();

    EXPECT_TRUE(status.refreshToken);
}

HWTEST_F(DeviceStatusEntryTest, BuildDeviceStatus_RefreshTokenFalse, TestSize.Level0)
{
    physicalStatus_.refreshToken = false;
    DeviceStatusEntry entry(physicalStatus_, []() {});
    entry.isSynced = true;

    DeviceStatus status = entry.BuildDeviceStatus();

    EXPECT_FALSE(status.refreshToken);
}

HWTEST_F(DeviceStatusEntryTest, Constructor_SupportedBusinessIds_001, TestSize.Level0)
{
    std::vector<BusinessId> hostBusinessIds = { static_cast<BusinessId>(10001), static_cast<BusinessId>(10002) };
    physicalStatus_.supportedBusinessIds = hostBusinessIds;

    DeviceStatusEntry entry(physicalStatus_, []() {}, hostBusinessIds);

    // sync empty -> effective degrades to hostSupportBusinessIds_ ∩ physicalCompanionBusinessIds_
    const auto &effective = entry.GetSupportedBusinessIds();
    ASSERT_EQ(effective.size(), 2u);
    EXPECT_EQ(effective[0], static_cast<BusinessId>(10001));
    EXPECT_EQ(effective[1], static_cast<BusinessId>(10002));
}

HWTEST_F(DeviceStatusEntryTest, Constructor_SupportedBusinessIds_Empty_001, TestSize.Level0)
{
    DeviceStatusEntry entry(physicalStatus_, []() {});

    EXPECT_TRUE(entry.GetSupportedBusinessIds().empty());
}

HWTEST_F(DeviceStatusEntryTest, SyncCompanionBusinessIds_TakesPriority_OverPhysical, TestSize.Level0)
{
    // host supports 10001/10002/10003; physical advertises 10001; sync advertises 10003.
    std::vector<BusinessId> hostBusinessIds = { static_cast<BusinessId>(10001), static_cast<BusinessId>(10002),
        static_cast<BusinessId>(10003) };
    physicalStatus_.supportedBusinessIds = { static_cast<BusinessId>(10001) };

    DeviceStatusEntry entry(physicalStatus_, []() {}, hostBusinessIds);
    // before sync: effective degrades to hostSupport ∩ physical = {10001}
    EXPECT_EQ(entry.GetSupportedBusinessIds(), std::vector<BusinessId>({ static_cast<BusinessId>(10001) }));

    entry.SetSyncCompanionBusinessIds({ static_cast<BusinessId>(10003) });
    // after sync: sync takes priority over physical -> hostSupport ∩ {10003} = {10003}
    EXPECT_EQ(entry.GetSupportedBusinessIds(), std::vector<BusinessId>({ static_cast<BusinessId>(10003) }));
}

HWTEST_F(DeviceStatusEntryTest, SetSyncCompanionBusinessIds_Empty_DegradesToPhysical, TestSize.Level0)
{
    std::vector<BusinessId> hostBusinessIds = { static_cast<BusinessId>(10001), static_cast<BusinessId>(10002) };
    physicalStatus_.supportedBusinessIds = { static_cast<BusinessId>(10001), static_cast<BusinessId>(10002) };

    DeviceStatusEntry entry(physicalStatus_, []() {}, hostBusinessIds);
    entry.SetSyncCompanionBusinessIds({ static_cast<BusinessId>(10001) });
    EXPECT_EQ(entry.GetSupportedBusinessIds(), std::vector<BusinessId>({ static_cast<BusinessId>(10001) }));

    // sync becomes empty -> effective degrades back to physical
    bool changed = entry.SetSyncCompanionBusinessIds({});
    EXPECT_TRUE(changed);
    EXPECT_EQ(entry.GetSupportedBusinessIds(),
        std::vector<BusinessId>({ static_cast<BusinessId>(10001), static_cast<BusinessId>(10002) }));
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
