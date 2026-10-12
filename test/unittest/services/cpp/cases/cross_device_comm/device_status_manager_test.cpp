/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "device_status_manager_test_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

HWTEST_F(DeviceStatusManagerTest, ShouldMonitorDeviceRespectsModeAndSubscriptions, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-keep";

    PhysicalDeviceKey otherKey = targetKey;
    otherKey.deviceId = "device-other";

    auto deviceKey = MakeDeviceKey(targetKey);
    auto subscription = ctx.manager->SubscribeDeviceStatus(deviceKey, SyncDemand::FOLLOW_SUBSCRIBE_MODE,
        [](const std::vector<DeviceStatus> &) {});
    EXPECT_TRUE(ctx.manager->ShouldMonitorDevice(targetKey));
    EXPECT_FALSE(ctx.manager->ShouldMonitorDevice(otherKey));

    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_ALL_DEVICES);
    EXPECT_TRUE(ctx.manager->ShouldMonitorDevice(otherKey));

    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_SUBSCRIBED_ONLY);
    subscription.reset();
    EXPECT_FALSE(ctx.manager->ShouldMonitorDevice(otherKey));
}

HWTEST_F(DeviceStatusManagerTest, ReconcileDevicesAddsAndRemovesDevices, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    auto statusA = MakePhysicalStatus("device-A", ChannelId::SOFTBUS, "DeviceA");
    auto statusB = MakePhysicalStatus("device-B", ChannelId::SOFTBUS, "DeviceB");

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { statusA, statusB }))
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { statusB }));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
    EXPECT_EQ(2u, ctx.manager->deviceStatusMap_.size());
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.count(statusA.physicalDeviceKey));
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.count(statusB.physicalDeviceKey));
    EXPECT_EQ("DeviceA", ctx.manager->deviceStatusMap_.at(statusA.physicalDeviceKey).physicalDeviceName);

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
    EXPECT_EQ(1u, ctx.manager->deviceStatusMap_.size());
    EXPECT_FALSE(ctx.manager->deviceStatusMap_.count(statusA.physicalDeviceKey));
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.count(statusB.physicalDeviceKey));
}

HWTEST_F(DeviceStatusManagerTest, SpecificDeviceSubscriptionTriggersRefreshOnSubscribeAndUnsubscribe, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-refresh";

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .Times(2)
        .WillRepeatedly(Return(std::vector<PhysicalDeviceStatus> {}));

    auto subscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey), SyncDemand::FOLLOW_SUBSCRIBE_MODE,
        [](const std::vector<DeviceStatus> &) {});
    ASSERT_NO_THROW(subscription.reset());
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(DeviceStatusManagerTest, GetDeviceStatus_IgnoresDeviceUserId, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-ignore-user", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // GetDeviceStatus locates a device by idType+deviceId only; deviceUserId is not a filter.
    DeviceKey keyWithDifferentUser = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    keyWithDifferentUser.deviceUserId = activeUserId_ + 1;

    auto result = ctx.manager->GetDeviceStatus(keyWithDifferentUser);
    EXPECT_TRUE(result.has_value());
}

HWTEST_F(DeviceStatusManagerTest, GetDeviceStatus_NotSynced, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-not-synced", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto result = ctx.manager->GetDeviceStatus(deviceKey);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(DeviceStatusManagerTest, GetChannelIdByDeviceKey_IgnoresDeviceUserId, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-channel-ignore-user", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // GetChannelIdByDeviceKey locates a device by idType+deviceId only; deviceUserId is not a filter.
    DeviceKey keyWithDifferentUser = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    keyWithDifferentUser.deviceUserId = activeUserId_ + 1;

    auto result = ctx.manager->GetChannelIdByDeviceKey(keyWithDifferentUser);
    EXPECT_TRUE(result.has_value());
}

HWTEST_F(DeviceStatusManagerTest, GetChannelIdByDeviceKey_DeviceNotFound, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    DeviceKey nonExistentKey;
    nonExistentKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    nonExistentKey.deviceId = "non-existent";
    nonExistentKey.deviceUserId = activeUserId_;

    auto result = ctx.manager->GetChannelIdByDeviceKey(nonExistentKey);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(DeviceStatusManagerTest, GetChannelIdByDeviceKey_InvalidChannelId, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-invalid-channel", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.channelId = ChannelId::INVALID;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto result = ctx.manager->GetChannelIdByDeviceKey(deviceKey);
    EXPECT_FALSE(result.has_value());
}

// A device attribute change is itself an invalidation event: the channel reporting a changed
// attribute forces a re-read even on a synced entry.
// A channel-view attribute change updates the entry and notifies subscribers only: no sync
// round is kicked from here, because peer-owned drift propagates via the peer's resync push
// and sync results cannot write back channel-owned fields.
HWTEST_F(DeviceStatusManagerTest, AttributeChange_NotifiesWithoutResyncRound, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-attr-change", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto notified = std::make_shared<bool>(false);
    auto seenModelInfo = std::make_shared<std::string>();
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, [notified, seenModelInfo](const std::vector<DeviceStatus> &statusList) {
            for (const auto &status : statusList) {
                if (status.deviceKey.deviceId == "device-attr-change") {
                    *notified = true;
                    *seenModelInfo = status.deviceModelInfo;
                }
            }
        });

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);

    // The channel now reports the same device under a different model info.
    auto changedStatus = MakePhysicalStatus("device-attr-change", ChannelId::SOFTBUS, "Device");
    changedStatus.deviceModelInfo = "model-v2";
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { changedStatus }));
    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*notified);
    EXPECT_EQ("model-v2", *seenModelInfo);
    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_EQ("model-v2", stored.deviceModelInfo);
    EXPECT_FALSE(stored.isSyncInProgress);
}

// Wearing state arrives on the physical channel and is never carried by sync: an
// isAuthMaintainActive-only change must still update the entry and notify subscribers
// (regression: the value froze at adoption time).
HWTEST_F(DeviceStatusManagerTest, AuthMaintainActiveChange_NotifiesSubscribersWithoutResync, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-wear-change", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto notified = std::make_shared<bool>(false);
    auto seenActive = std::make_shared<std::optional<bool>>();
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, [notified, seenActive](const std::vector<DeviceStatus> &statusList) {
            for (const auto &status : statusList) {
                if (status.deviceKey.deviceId == "device-wear-change") {
                    *notified = true;
                    *seenActive = status.isAuthMaintainActive;
                }
            }
        });

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);

    // The channel now reports the same device as not worn; nothing else changes.
    auto notWornStatus = physicalStatus;
    notWornStatus.isAuthMaintainActive = false;
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { notWornStatus }));
    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*notified);
    ASSERT_TRUE(seenActive->has_value());
    EXPECT_FALSE(seenActive->value());
    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    ASSERT_TRUE(stored.isAuthMaintainActive.has_value());
    EXPECT_FALSE(stored.isAuthMaintainActive.value());
    EXPECT_FALSE(stored.isSyncInProgress);
}

HWTEST_F(DeviceStatusManagerTest, UnsubscribeDeviceStatus_NotFound, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    bool result = ctx.manager->UnsubscribeDeviceStatus(INT32_99999);
    EXPECT_FALSE(result);
}

HWTEST_F(DeviceStatusManagerTest, UnsubscribeDeviceStatus_Success, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto subscription = ctx.manager->SubscribeDeviceStatus([](const std::vector<DeviceStatus> &) {});
    SubscribeId subscriptionId = ctx.manager->subscriptions_.back().subscriptionId;

    bool result = ctx.manager->UnsubscribeDeviceStatus(subscriptionId);
    EXPECT_TRUE(result);
}

// OutboundRequest::BringPeerOnline subscribes the peer for the whole request, so an unpaired peer
// (its DeviceKey still carries no user fields) survives a narrowing while its sync is on the wire.
HWTEST_F(DeviceStatusManagerTest, SubscribeDeviceStatus_UnpairedPeerSurvivesNarrowing, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    auto physicalStatus = MakePhysicalStatus("device-sync-in-flight", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
    ASSERT_EQ(1u, ctx.manager->deviceStatusMap_.count(physicalStatus.physicalDeviceKey));

    bool waiterSettled = false;
    ResultCode waiterResult = ResultCode::SUCCESS;
    auto &entry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    entry.isSyncInProgress = true;
    entry.syncWaiters.push_back([&waiterSettled, &waiterResult](ResultCode resultCode) {
        waiterSettled = true;
        waiterResult = resultCode;
    });

    DeviceKey peerDeviceKey {};
    peerDeviceKey.idType = physicalStatus.physicalDeviceKey.idType;
    peerDeviceKey.deviceId = physicalStatus.physicalDeviceKey.deviceId;
    auto subscription = ctx.manager->SubscribeDeviceStatus(peerDeviceKey, SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);
    ASSERT_NE(subscription, nullptr);

    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_SUBSCRIBED_ONLY);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(1u, ctx.manager->deviceStatusMap_.count(physicalStatus.physicalDeviceKey));
    EXPECT_FALSE(waiterSettled);

    auto &kept = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    kept.isSyncInProgress = false;
    kept.NotifySyncWaiters(ResultCode::SUCCESS);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(waiterSettled);
    EXPECT_EQ(ResultCode::SUCCESS, waiterResult);

    // Request over: releasing the subscription puts the device back out of the narrowed scope.
    subscription.reset();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(0u, ctx.manager->deviceStatusMap_.count(physicalStatus.physicalDeviceKey));
}

HWTEST_F(DeviceStatusManagerTest, CollectFilteredDevices_NullChannel, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto channelMgrWithNull = std::make_shared<ChannelManager>(std::vector<std::shared_ptr<ICrossDeviceChannel>> {
        std::static_pointer_cast<ICrossDeviceChannel>(ctx.mockChannel), nullptr });

    auto mgr = DeviceStatusManager::Create({ BusinessId::DEFAULT }, ctx.connectionMgr, channelMgrWithNull,
        ctx.localStatusManager);
    ASSERT_NE(mgr, nullptr);
    mgr->SetSubscribeMode(SUBSCRIBE_MODE_ALL_DEVICES);

    auto filteredDevices = mgr->CollectFilteredDevices();
}

// The resync pass over the device list is a conditional reevaluation, not an unconditional
// re-read: a synced entry only re-syncs when the template window is unconfirmed.
HWTEST_F(DeviceStatusManagerTest, ReconcileDevices_WithResync, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    ctx.guard->GetTimeKeeper().SetSteadyTime(200); // window opens after the entry's last sync
    ctx.manager->SetTemplateStatusSubscribed(true);

    auto statusA = MakePhysicalStatus("device-resync-A", ChannelId::SOFTBUS, "DeviceA");
    DeviceStatusEntry entryA(statusA, []() {});
    entryA.isSynced = true;
    entryA.lastSyncTimeMs = 100;
    ctx.manager->deviceStatusMap_.emplace(statusA.physicalDeviceKey, std::move(entryA));

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { statusA }));

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(Invoke([](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                             SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
            return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                SyncDeviceStatusCallback {});
        }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    ASSERT_NO_THROW(ctx.manager->ReconcileDevices(DeviceReconcilePolicy::REEVALUATE_ALL));
}

HWTEST_F(DeviceStatusManagerTest, HandleChannelDeviceStatusChange, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices()).WillOnce(Return(std::vector<PhysicalDeviceStatus> {}));

    ASSERT_NO_THROW(
        ctx.manager->HandleChannelDeviceStatusChange(ChannelId::SOFTBUS, std::vector<PhysicalDeviceStatus> {}));
}

HWTEST_F(DeviceStatusManagerTest, NegotiateProtocol_MultipleProtocols, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::INVALID, ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1, ProtocolId::INVALID };

    std::vector<ProtocolId> remoteProtocols = { ProtocolId::VERSION_1, ProtocolId::INVALID };
    auto result = ctx.manager->NegotiateProtocol(remoteProtocols);

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(ProtocolId::INVALID, result.value());
}

HWTEST_F(DeviceStatusManagerTest, GetAllDeviceStatus_MultipleSynced, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.companionCapabilities = { Capability::TOKEN_AUTH };

    auto status1 = MakePhysicalStatus("device-all-1", ChannelId::SOFTBUS, "Device1");
    DeviceStatusEntry entry1(status1, []() {});
    entry1.isSynced = true;
    entry1.protocolId = ProtocolId::VERSION_1;
    entry1.capabilities = { Capability::TOKEN_AUTH };
    ctx.manager->deviceStatusMap_.emplace(status1.physicalDeviceKey, std::move(entry1));

    auto status2 = MakePhysicalStatus("device-all-2", ChannelId::SOFTBUS, "Device2");
    DeviceStatusEntry entry2(status2, []() {});
    entry2.isSynced = true;
    entry2.protocolId = ProtocolId::VERSION_1;
    entry2.capabilities = { Capability::TOKEN_AUTH };
    ctx.manager->deviceStatusMap_.emplace(status2.physicalDeviceKey, std::move(entry2));

    auto status3 = MakePhysicalStatus("device-all-3", ChannelId::SOFTBUS, "Device3");
    DeviceStatusEntry entry3(status3, []() {});
    entry3.isSynced = false;
    ctx.manager->deviceStatusMap_.emplace(status3.physicalDeviceKey, std::move(entry3));

    auto allDevices = ctx.manager->GetAllDeviceStatus();
    EXPECT_EQ(2u, allDevices.size());
}

HWTEST_F(DeviceStatusManagerTest, GetAllDeviceStatus_IncludeUnsyncedFollowsReportUnsynced, TestSize.Level0)
{
    auto ctx = SetupTestContext();

    auto syncedStatus = MakePhysicalStatus("device-synced", ChannelId::SOFTBUS, "synced");
    DeviceStatusEntry syncedEntry(syncedStatus, []() {});
    syncedEntry.isSynced = true;
    ctx.manager->deviceStatusMap_.emplace(syncedStatus.physicalDeviceKey, std::move(syncedEntry));

    auto reportedStatus = MakePhysicalStatus("device-unsynced-reported", ChannelId::SOFTBUS, "reported");
    reportedStatus.reportUnsynced = true;
    DeviceStatusEntry reportedEntry(reportedStatus, []() {});
    ctx.manager->deviceStatusMap_.emplace(reportedStatus.physicalDeviceKey, std::move(reportedEntry));

    auto suppressedStatus = MakePhysicalStatus("device-unsynced-suppressed", ChannelId::SOFTBUS, "suppressed");
    DeviceStatusEntry suppressedEntry(suppressedStatus, []() {});
    ctx.manager->deviceStatusMap_.emplace(suppressedStatus.physicalDeviceKey, std::move(suppressedEntry));

    auto allDevices = ctx.manager->GetAllDeviceStatus();
    ASSERT_EQ(1u, allDevices.size());
    EXPECT_EQ("device-synced", allDevices[0].deviceKey.deviceId);

    auto includingUnsynced = ctx.manager->GetAllDeviceStatus(DeviceStatusFilter::INCLUDE_UNSYNCED);
    ASSERT_EQ(2u, includingUnsynced.size());
    EXPECT_EQ("device-synced", includingUnsynced[0].deviceKey.deviceId);
    EXPECT_EQ("device-unsynced-reported", includingUnsynced[1].deviceKey.deviceId);
    EXPECT_TRUE(includingUnsynced[0].isOnline);
    EXPECT_FALSE(includingUnsynced[1].isOnline);
}

HWTEST_F(DeviceStatusManagerTest, SubscribeDeviceStatus_SpecificDevice_RefreshTriggered, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-specific-sub";

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .Times(AtLeast(1))
        .WillRepeatedly(Return(std::vector<PhysicalDeviceStatus> {}));

    ASSERT_NO_THROW(auto subscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey),
                        SyncDemand::FOLLOW_SUBSCRIBE_MODE, [](const std::vector<DeviceStatus> &) {}));
}

HWTEST_F(DeviceStatusManagerTest, NotifySubscribers_WithNullCallback, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->subscriptions_.push_back({ 1, std::nullopt, nullptr });

    auto status = MakePhysicalStatus("device-notify", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(status, []() {});
    entry.isSynced = true;
    entry.protocolId = ProtocolId::VERSION_1;
    entry.capabilities = { Capability::TOKEN_AUTH };
    ctx.manager->deviceStatusMap_.emplace(status.physicalDeviceKey, std::move(entry));

    ASSERT_NO_THROW(ctx.manager->NotifySubscribers());
}

HWTEST_F(DeviceStatusManagerTest, AddOrUpdateDevices_DetectsRefreshTokenChange, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    auto physicalStatus = MakePhysicalStatus("device-refresh-token", ChannelId::SOFTBUS, "Device");
    physicalStatus.refreshToken = false;

    // First add with refreshToken=false
    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
    ASSERT_EQ(1u, ctx.manager->deviceStatusMap_.size());
    EXPECT_FALSE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).refreshToken);

    // Now update with refreshToken=true
    auto updatedStatus = physicalStatus;
    updatedStatus.refreshToken = true;

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { updatedStatus }));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
    ASSERT_EQ(1u, ctx.manager->deviceStatusMap_.size());
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).refreshToken);
}

HWTEST_F(DeviceStatusManagerTest, AddOrUpdateDevices_DetectsReportUnsyncedChange, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    auto physicalStatus = MakePhysicalStatus("device-report-unsynced", ChannelId::SOFTBUS, "Device");
    physicalStatus.reportUnsynced = false;

    // First add with reportUnsynced=false
    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
    ASSERT_EQ(1u, ctx.manager->deviceStatusMap_.size());
    EXPECT_FALSE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).reportUnsynced);

    // Now update with reportUnsynced=true
    auto updatedStatus = physicalStatus;
    updatedStatus.reportUnsynced = true;

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { updatedStatus }));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
    ASSERT_EQ(1u, ctx.manager->deviceStatusMap_.size());
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).reportUnsynced);
}

HWTEST_F(DeviceStatusManagerTest, GetDeviceStatus_IncludesRefreshToken, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.hostCapabilities = { Capability::TOKEN_AUTH };

    auto physicalStatus = MakePhysicalStatus("device-get-refresh", ChannelId::SOFTBUS, "Device");
    physicalStatus.refreshToken = true;
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.protocolId = ProtocolId::VERSION_1;
    entry.capabilities = { Capability::TOKEN_AUTH };
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto result = ctx.manager->GetDeviceStatus(deviceKey);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->refreshToken);
}

HWTEST_F(DeviceStatusManagerTest, GetAllDeviceStatus_IncludesRefreshToken, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.hostCapabilities = { Capability::TOKEN_AUTH };

    auto physicalStatus = MakePhysicalStatus("device-all-refresh", ChannelId::SOFTBUS, "Device");
    physicalStatus.refreshToken = true;
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.protocolId = ProtocolId::VERSION_1;
    entry.capabilities = { Capability::TOKEN_AUTH };
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto allDevices = ctx.manager->GetAllDeviceStatus();
    ASSERT_EQ(1u, allDevices.size());
    EXPECT_TRUE(allDevices[0].refreshToken);
}

HWTEST_F(DeviceStatusManagerTest, AddOrUpdateDevices_NewDevice_ComputesEffectiveBusinessIds, TestSize.Level0)
{
    auto ctx = SetupTestContextWithBusinessIds({ static_cast<BusinessId>(10001), static_cast<BusinessId>(10002) });
    ASSERT_NE(ctx.manager, nullptr);
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    auto physicalStatus = MakePhysicalStatus("device-new", ChannelId::SOFTBUS, "Device");
    physicalStatus.supportedBusinessIds = { static_cast<BusinessId>(10002), static_cast<BusinessId>(10003) };

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(Invoke([](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                             SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
            return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                SyncDeviceStatusCallback {});
        }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);

    auto it = ctx.manager->deviceStatusMap_.find(physicalStatus.physicalDeviceKey);
    ASSERT_NE(it, ctx.manager->deviceStatusMap_.end());
    ASSERT_EQ(it->second.GetSupportedBusinessIds().size(), 1u);
    EXPECT_EQ(it->second.GetSupportedBusinessIds()[0], static_cast<BusinessId>(10002));
}

HWTEST_F(DeviceStatusManagerTest, AddOrUpdateDevices_NewDevice_EmptyDeviceIds, TestSize.Level0)
{
    auto ctx = SetupTestContextWithBusinessIds({ static_cast<BusinessId>(10001) });
    ASSERT_NE(ctx.manager, nullptr);
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    auto physicalStatus = MakePhysicalStatus("device-empty", ChannelId::SOFTBUS, "Device");

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(Invoke([](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                             SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
            return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                SyncDeviceStatusCallback {});
        }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);

    auto it = ctx.manager->deviceStatusMap_.find(physicalStatus.physicalDeviceKey);
    ASSERT_NE(it, ctx.manager->deviceStatusMap_.end());
    EXPECT_TRUE(it->second.GetSupportedBusinessIds().empty());
}

HWTEST_F(DeviceStatusManagerTest, AddOrUpdateDevices_SupportedBusinessIdsChanged, TestSize.Level0)
{
    auto ctx = SetupTestContextWithBusinessIds(
        { static_cast<BusinessId>(10001), static_cast<BusinessId>(10002), static_cast<BusinessId>(10003) });
    ASSERT_NE(ctx.manager, nullptr);
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    auto physicalStatus = MakePhysicalStatus("device-biz-change", ChannelId::SOFTBUS, "Device");
    physicalStatus.supportedBusinessIds = { static_cast<BusinessId>(10001), static_cast<BusinessId>(10002) };

    // Pre-existing entry, not yet synced (sync empty): effective is driven by the physical ids.
    DeviceStatusEntry entry(physicalStatus, []() {}, ctx.manager->hostSupportBusinessIds_);
    entry.isSynced = true;
    entry.protocolId = ProtocolId::VERSION_1;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto updatedStatus = MakePhysicalStatus("device-biz-change", ChannelId::SOFTBUS, "Device");
    updatedStatus.supportedBusinessIds = { static_cast<BusinessId>(10003) };

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { updatedStatus }));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);

    auto it = ctx.manager->deviceStatusMap_.find(physicalStatus.physicalDeviceKey);
    ASSERT_NE(it, ctx.manager->deviceStatusMap_.end());
    // physical ids changed -> effective = hostSupport ∩ {10003} = {10003}
    ASSERT_EQ(it->second.GetSupportedBusinessIds().size(), 1u);
    EXPECT_EQ(it->second.GetSupportedBusinessIds()[0], static_cast<BusinessId>(10003));
}

HWTEST_F(DeviceStatusManagerTest, AddOrUpdateDevices_SupportedBusinessIdsUnchanged, TestSize.Level0)
{
    auto ctx = SetupTestContextWithBusinessIds({ static_cast<BusinessId>(10001) });
    ASSERT_NE(ctx.manager, nullptr);
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    auto physicalStatus = MakePhysicalStatus("device-biz-same", ChannelId::SOFTBUS, "Device");
    physicalStatus.supportedBusinessIds = { static_cast<BusinessId>(10001) };

    DeviceStatusEntry entry(physicalStatus, []() {}, ctx.manager->hostSupportBusinessIds_);
    entry.isSynced = true;
    entry.protocolId = ProtocolId::VERSION_1;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);

    auto it = ctx.manager->deviceStatusMap_.find(physicalStatus.physicalDeviceKey);
    ASSERT_NE(it, ctx.manager->deviceStatusMap_.end());
    ASSERT_EQ(it->second.GetSupportedBusinessIds().size(), 1u);
    EXPECT_EQ(it->second.GetSupportedBusinessIds()[0], static_cast<BusinessId>(10001));
}

// A device that disappears from the channel list while a sync attempt is pending is removed by
// ReconcileDevices; the onResult parked on the entry must be told GENERAL_ERROR instead of
// dangling forever.
HWTEST_F(DeviceStatusManagerTest, ReconcileDevicesNotifiesCallbackWhenSyncingDeviceRemoved, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    bool onResultCalled = false;
    ResultCode notifiedResult = ResultCode::SUCCESS;
    auto physicalStatus = MakePhysicalStatus("device-removed-pending", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    entry.inProgressAttemptId = 9;
    entry.syncWaiters.push_back([&onResultCalled, &notifiedResult](ResultCode resultCode) {
        onResultCalled = true;
        notifiedResult = resultCode;
    });
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // The channel no longer reports the device, so ReconcileDevices must drop it.
    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices()).WillOnce(Return(std::vector<PhysicalDeviceStatus> {}));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(ResultCode::GENERAL_ERROR, notifiedResult);
    EXPECT_EQ(0u, ctx.manager->deviceStatusMap_.size());
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
