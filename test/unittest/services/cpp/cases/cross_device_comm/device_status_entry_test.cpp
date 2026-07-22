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

#include <memory>

#include "device_status_entry.h"
#include "relative_timer.h"

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
        physicalStatus_.useSyncDeviceName = true;
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
    EXPECT_EQ(entry.physicalDeviceName, "TestDevice");
    EXPECT_TRUE(entry.syncDeviceName.empty());
    EXPECT_TRUE(entry.isAuthMaintainActive);
    EXPECT_FALSE(entry.isSynced);
    EXPECT_FALSE(entry.isSyncInProgress);
    EXPECT_TRUE(entry.useSyncDeviceName);
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

HWTEST_F(DeviceStatusEntryTest, BuildDeviceStatus_PrefersSyncDeviceName, TestSize.Level0)
{
    DeviceStatusEntry entry(physicalStatus_, []() {});
    entry.isSynced = true;
    entry.syncDeviceName = "SyncedName";

    DeviceStatus status = entry.BuildDeviceStatus();

    // Non-empty sync name wins over the physical name.
    EXPECT_EQ(status.deviceName, "SyncedName");
}

HWTEST_F(DeviceStatusEntryTest, BuildDeviceStatus_FallsBackToPhysicalWhenSyncEmpty, TestSize.Level0)
{
    DeviceStatusEntry entry(physicalStatus_, []() {});
    entry.isSynced = true;
    // syncDeviceName left empty, emulating an old peer that does not send deviceName.

    DeviceStatus status = entry.BuildDeviceStatus();

    // Empty sync name falls back to the physical name.
    EXPECT_EQ(status.deviceName, "TestDevice");
}

HWTEST_F(DeviceStatusEntryTest, BuildDeviceStatus_PrefersPhysicalWhenSyncNameDisabled, TestSize.Level0)
{
    DeviceStatusEntry entry(physicalStatus_, []() {});
    entry.isSynced = true;
    entry.syncDeviceName = "SyncedName";
    entry.useSyncDeviceName = false;

    DeviceStatus status = entry.BuildDeviceStatus();

    // When the sync-name gate is off, the physical name wins even with a non-empty sync name.
    EXPECT_EQ(status.deviceName, "TestDevice");
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

HWTEST_F(DeviceStatusEntryTest, BuildDeviceStatus_IncludesLastSyncTimeMs, TestSize.Level0)
{
    DeviceStatusEntry entry(physicalStatus_, []() {});
    entry.isSynced = true;
    entry.lastSyncTimeMs = 12345;

    DeviceStatus status = entry.BuildDeviceStatus();

    EXPECT_EQ(status.lastSyncTimeMs, 12345u);
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

// OnSyncFailure arms the backoff timer; firing it invokes the retry callback passed at
// construction (the sync retry-fire re-entry point).
HWTEST_F(DeviceStatusEntryTest, OnSyncFailure_ArmsRetryThatFiresCallback, TestSize.Level0)
{
    auto retryCallCount = std::make_shared<int>(0);
    DeviceStatusEntry entry(physicalStatus_, [retryCallCount]() { (*retryCallCount)++; });

    entry.OnSyncFailure(); // arms the retry timer

    RelativeTimer::GetInstance().ExecuteAll();
    EXPECT_EQ(*retryCallCount, 1);
}

// External sync trigger (ResetRetry) clears the backoff delay while preserving the failure
// budget — the dual-counter contract mirrored from BackoffRetryTimer::ResetBackoff.
HWTEST_F(DeviceStatusEntryTest, ResetRetry_ClearsBackoffKeepsBudget, TestSize.Level0)
{
    auto retryCallCount = std::make_shared<int>(0);
    DeviceStatusEntry entry(physicalStatus_, [retryCallCount]() { (*retryCallCount)++; });

    entry.OnSyncFailure(); // backoffStep=1, failureCount=1
    entry.OnSyncFailure(); // backoffStep=2, failureCount=2
    ASSERT_NE(entry.syncRetryTimer_, nullptr);
    EXPECT_EQ(entry.syncRetryTimer_->backoffStep_, 2u);
    EXPECT_EQ(entry.syncRetryTimer_->failureCount_, 2u);

    entry.ResetRetry(); // external trigger: clear delay, cancel pending, keep budget

    EXPECT_EQ(entry.syncRetryTimer_->backoffStep_, 0u);
    EXPECT_EQ(entry.syncRetryTimer_->failureCount_, 2u);

    RelativeTimer::GetInstance().ExecuteAll();
    EXPECT_EQ(*retryCallCount, 0); // pending timer cancelled
}

// A sync failure schedules the retry callback through the (fake) RelativeTimer;
// draining pending timers must fire it exactly once.
HWTEST_F(DeviceStatusEntryTest, OnSyncFailure_SchedulesRetry, TestSize.Level0)
{
    auto retryCount = std::make_shared<int>(0);
    DeviceStatusEntry entry(physicalStatus_, [retryCount]() { (*retryCount)++; });

    entry.OnSyncFailure();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(*retryCount, 1);
}

// OnSyncAbort terminates the retry process and clears backoff state: a retry
// that was already pending must not fire after the abort.
HWTEST_F(DeviceStatusEntryTest, OnSyncAbort_CancelsPendingRetry, TestSize.Level0)
{
    auto retryCount = std::make_shared<int>(0);
    DeviceStatusEntry entry(physicalStatus_, [retryCount]() { (*retryCount)++; });

    entry.OnSyncFailure();
    entry.OnSyncAbort();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(*retryCount, 0);
}

// OnSyncAbort is a safe no-op when no retry is pending.
HWTEST_F(DeviceStatusEntryTest, OnSyncAbort_NoOpWhenIdle, TestSize.Level0)
{
    auto retryCount = std::make_shared<int>(0);
    DeviceStatusEntry entry(physicalStatus_, [retryCount]() { (*retryCount)++; });

    entry.OnSyncAbort();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(*retryCount, 0);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
