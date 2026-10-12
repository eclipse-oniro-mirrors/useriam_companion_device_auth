/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "relative_timer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

HWTEST_F(DeviceStatusManagerTest, HandleSyncResultSuccessPropagatesNegotiatedStatus, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.companionCapabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };

    auto callbackInvoked = std::make_shared<bool>(false);
    size_t callbackCount = 0;
    auto subscription = ctx.manager->SubscribeDeviceStatus(
        [callbackInvoked, &callbackCount](const std::vector<DeviceStatus> &statusList) {
            *callbackInvoked = true;
            callbackCount++;
            ASSERT_EQ(1u, statusList.size());
            EXPECT_EQ("device-1", statusList[0].deviceKey.deviceId);
            EXPECT_EQ(ProtocolId::VERSION_1, statusList[0].protocolId);
            ASSERT_EQ(1u, statusList[0].capabilities.size());
            EXPECT_EQ(Capability::TOKEN_AUTH, statusList[0].capabilities[0]);
        });
    (void)subscription;

    auto physicalStatus = MakePhysicalStatus("device-1", ChannelId::SOFTBUS, "deviceName");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    SyncDeviceStatus syncStatus;
    syncStatus.needSync = true;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "tester";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;

    ctx.manager->HandleSyncResult(deviceKey, 0, SUCCESS, syncStatus);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
    EXPECT_EQ(1u, callbackCount);
    auto result = ctx.manager->GetDeviceStatus(deviceKey);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(ChannelId::SOFTBUS, result->channelId);
    const auto &storedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(storedEntry.isSynced);
    EXPECT_FALSE(storedEntry.isSyncInProgress);
    auto allDevices = ctx.manager->GetAllDeviceStatus();
    ASSERT_EQ(1u, allDevices.size());
    auto channelId = ctx.manager->GetChannelIdByDeviceKey(deviceKey);
    ASSERT_TRUE(channelId.has_value());
    EXPECT_EQ(ChannelId::SOFTBUS, channelId.value());
}

HWTEST_F(DeviceStatusManagerTest, HandleSyncResultSuccessRecordsSyncTime, TestSize.Level0)
{
    auto ctx = SetupTestContext();

    constexpr uint64_t syncSteadyTimeMs = 98765;
    ctx.guard->GetTimeKeeper().SetSteadyTime(syncSteadyTimeMs);

    auto physicalStatus = MakePhysicalStatus("device-1", ChannelId::SOFTBUS, "deviceName");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    SyncDeviceStatus syncStatus;
    ctx.manager->HandleSyncResult(deviceKey, 0, SUCCESS, syncStatus);

    TaskRunnerManager::GetInstance().ExecuteAll();

    // A successful sync stamps the steady-clock time so isConfirmed can reflect it downstream.
    auto result = ctx.manager->GetDeviceStatus(deviceKey);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->lastSyncTimeMs, syncSteadyTimeMs);
}

HWTEST_F(DeviceStatusManagerTest, HandleSyncResultFailureDoesNotRecordSyncTime, TestSize.Level0)
{
    auto ctx = SetupTestContext();

    constexpr uint64_t syncSteadyTimeMs = 98765;
    ctx.guard->GetTimeKeeper().SetSteadyTime(syncSteadyTimeMs);

    auto physicalStatus = MakePhysicalStatus("device-1", ChannelId::SOFTBUS, "deviceName");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    SyncDeviceStatus syncStatus;
    ctx.manager->HandleSyncResult(deviceKey, 0, GENERAL_ERROR, syncStatus);

    TaskRunnerManager::GetInstance().ExecuteAll();

    // A failed sync must not count as a real-time confirmation.
    const auto &storedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_EQ(storedEntry.lastSyncTimeMs, 0u);
}

HWTEST_F(DeviceStatusManagerTest, AttachOrStartDeviceSyncFailsWhenRequestCreationFails, TestSize.Level0)
{
    auto ctx = SetupTestContext();

    auto physicalStatus = MakePhysicalStatus("device-sync-fail-factory", ChannelId::SOFTBUS, "Device");
    // Subscribe while the entry does not exist yet: a registration that adds a demand would
    // otherwise start its own round (demand-added reevaluation) and consume the factory mock.
    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(deviceKey, SyncDemand::FOLLOW_SUBSCRIBE_MODE,
        [](const std::vector<DeviceStatus> &) {});

    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // Later subscriptions run a rescan: keep the channel reporting the device so the emplaced
    // entry survives them.
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    auto notified = std::make_shared<bool>(false);
    auto subscription =
        ctx.manager->SubscribeDeviceStatus([notified](const std::vector<DeviceStatus> &) { *notified = true; });
    (void)subscription;

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);

    ctx.manager->AttachOrStartDeviceSync(physicalStatus.physicalDeviceKey, SyncTriggerReason::RESYNC);
    const auto &failedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(failedEntry.isSynced);
    EXPECT_FALSE(failedEntry.isSyncInProgress);
    EXPECT_FALSE(*notified);
}

HWTEST_F(DeviceStatusManagerTest, AttachOrStartDeviceSyncFailsWhenRequestStartFails, TestSize.Level0)
{
    auto ctx = SetupTestContext();

    auto physicalStatus = MakePhysicalStatus("device-sync-fail-start", ChannelId::SOFTBUS, "Device");
    // Subscribe while the entry does not exist yet (see device-sync-fail-factory above).
    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(deviceKey, SyncDemand::FOLLOW_SUBSCRIBE_MODE,
        [](const std::vector<DeviceStatus> &) {});

    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // Later subscriptions run a rescan: keep the channel reporting the device so the emplaced
    // entry survives them.
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    auto notified = std::make_shared<bool>(false);
    auto subscription =
        ctx.manager->SubscribeDeviceStatus([notified](const std::vector<DeviceStatus> &) { *notified = true; });
    (void)subscription;

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(Invoke([](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                             SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
            (void)callback;
            return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                SyncDeviceStatusCallback {});
        }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(false));

    ctx.manager->AttachOrStartDeviceSync(physicalStatus.physicalDeviceKey, SyncTriggerReason::RESYNC);
    const auto &failedEntry2 = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(failedEntry2.isSynced);
    EXPECT_FALSE(failedEntry2.isSyncInProgress);
    EXPECT_FALSE(*notified);
}

HWTEST_F(DeviceStatusManagerTest, HandleSyncResultFailureMarksEntryAndSkipsNotification, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-2", ChannelId::SOFTBUS, "deviceName");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // Set up mock to return the test device to prevent ReconcileDevices from removing it
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription =
        ctx.manager->SubscribeDeviceStatus([callbackInvoked](const std::vector<DeviceStatus> &statusList) {
            (void)statusList;
            *callbackInvoked = true;
        });
    (void)subscription;

    SyncDeviceStatus syncStatus;
    syncStatus.needSync = true;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "tester";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;
    ctx.manager->HandleSyncResult(deviceKey, 0, GENERAL_ERROR, syncStatus);

    EXPECT_FALSE(*callbackInvoked);
    const auto &failedEntry3 = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(failedEntry3.isSynced);
    EXPECT_FALSE(failedEntry3.isSyncInProgress);
    EXPECT_FALSE(ctx.manager->GetDeviceStatus(deviceKey).has_value());
}

HWTEST_F(DeviceStatusManagerTest, AttachOrStartDeviceSyncStartsRequestAndHandlesCallback, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.companionCapabilities = { Capability::TOKEN_AUTH };

    auto physicalStatus = MakePhysicalStatus("device-sync", ChannelId::SOFTBUS, "DeviceSync");
    // Subscribe while the entry does not exist yet: a demand-adding registration would start
    // its own round and consume the factory expectations below.
    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(deviceKey, SyncDemand::FOLLOW_SUBSCRIBE_MODE,
        [](const std::vector<DeviceStatus> &) {});

    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // Later subscriptions run a rescan: keep the channel reporting the device so the emplaced
    // entry survives them.
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    auto notified = std::make_shared<bool>(false);
    auto subscription = ctx.manager->SubscribeDeviceStatus(
        [notified](const std::vector<DeviceStatus> &statusList) { *notified = !statusList.empty(); });
    (void)subscription;

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(Invoke([](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                             SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
            (void)callback;
            auto request = std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode,
                triggerReason, SyncDeviceStatusCallback {});
            return request;
        }));

    EXPECT_CALL(ctx.guard->GetRequestManager(), Start)
        .WillOnce(DoAll(Invoke([&ctx, &physicalStatus](const std::shared_ptr<IRequest> &request) {
            EXPECT_NE(nullptr, request);
            const auto &inProgressEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
            EXPECT_TRUE(inProgressEntry.isSyncInProgress);
        }),
            Return(true)));

    ctx.manager->AttachOrStartDeviceSync(physicalStatus.physicalDeviceKey, SyncTriggerReason::RESYNC);
    uint64_t attemptId = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).inProgressAttemptId;
    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "remote-user";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;
    ctx.manager->HandleSyncResult(deviceKey, attemptId, SUCCESS, syncStatus);

    TaskRunnerManager::GetInstance().ExecuteAll();

    const auto &storedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(storedEntry.isSynced);
    EXPECT_FALSE(storedEntry.isSyncInProgress);
    EXPECT_EQ("remote-user", storedEntry.deviceUserName);
    EXPECT_TRUE(notified);
}

HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_IgnoresDeviceUserId, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-sync-ignore-user", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // HandleSyncResult no longer filters by deviceUserId. The device's userId comes from the
    // sync response (syncDeviceStatus.deviceUserKey), not from the active user.
    DeviceKey keyWithDifferentUser = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    keyWithDifferentUser.deviceUserId = activeUserId_ + 1;

    int32_t reportedDeviceUserId = activeUserId_ + 1;
    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "user";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;
    syncStatus.deviceUserKey = UserKey { reportedDeviceUserId, INVALID_SUB_PROFILE_ID };

    ASSERT_NO_THROW(ctx.manager->HandleSyncResult(keyWithDifferentUser, 0, SUCCESS, syncStatus));

    const auto &syncedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(syncedEntry.isSynced);
    EXPECT_EQ(reportedDeviceUserId, syncedEntry.deviceUserKey.userId);
}

HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_DeviceNotInCache, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    DeviceKey nonExistentKey;
    nonExistentKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    nonExistentKey.deviceId = "non-existent-sync";
    nonExistentKey.deviceUserId = activeUserId_;

    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "user";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;

    ASSERT_NO_THROW(ctx.manager->HandleSyncResult(nonExistentKey, 0, SUCCESS, syncStatus));
}

HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_EmptySyncStatus, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-empty-sync", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription =
        ctx.manager->SubscribeDeviceStatus([callbackInvoked](const std::vector<DeviceStatus> &statusList) {
            *callbackInvoked = true;
            ASSERT_EQ(1u, statusList.size());
            EXPECT_EQ("device-empty-sync", statusList[0].deviceKey.deviceId);
            // Empty sync result should have default/empty values
            EXPECT_EQ(ProtocolId::INVALID, statusList[0].protocolId);
            EXPECT_TRUE(statusList[0].capabilities.empty());
        });
    (void)subscription;

    // Empty SyncDeviceStatus (needSync=false scenario)
    SyncDeviceStatus emptySyncStatus;
    emptySyncStatus.needSync = false; // Explicitly set to skip protocol negotiation
    ctx.manager->HandleSyncResult(deviceKey, 0, SUCCESS, emptySyncStatus);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
    const auto &syncedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(syncedEntry.isSynced);
    EXPECT_FALSE(syncedEntry.isSyncInProgress);
    // Verify default values for empty sync
    EXPECT_EQ(ProtocolId::INVALID, syncedEntry.protocolId);
    EXPECT_TRUE(syncedEntry.capabilities.empty());
    auto result = ctx.manager->GetDeviceStatus(deviceKey);
    ASSERT_TRUE(result.has_value());
}

HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_NoCommonProtocol, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.companionCapabilities = { Capability::TOKEN_AUTH };

    auto physicalStatus = MakePhysicalStatus("device-no-protocol", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    SyncDeviceStatus syncStatus;
    syncStatus.needSync = true;
    syncStatus.protocolIdList = { static_cast<ProtocolId>(INT32_999) };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "user";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;

    ctx.manager->HandleSyncResult(deviceKey, 0, SUCCESS, syncStatus);

    const auto &entry2 = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(entry2.isSynced);
    EXPECT_FALSE(entry2.isSyncInProgress);
}

// Negotiation failure is terminal and must not advance any success side effect: lastSyncTimeMs
// feeds the template "isConfirmed" judgment downstream, so stamping it on a round that failed to
// apply would make this failure count as confirmed later.
HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_NoCommonProtocolKeepsSyncTimeAndAbortsRetry, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };

    constexpr uint64_t syncSteadyTimeMs = 98765;
    ctx.guard->GetTimeKeeper().SetSteadyTime(syncSteadyTimeMs);

    auto retryCount = std::make_shared<int>(0);
    bool onResultCalled = false;
    ResultCode notifiedResult = ResultCode::SUCCESS;
    auto physicalStatus = MakePhysicalStatus("device-nego-fail", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, [retryCount]() { (*retryCount)++; });
    entry.isSyncInProgress = true;
    entry.syncWaiters.push_back([&onResultCalled, &notifiedResult](ResultCode resultCode) {
        onResultCalled = true;
        notifiedResult = resultCode;
    });
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    SyncDeviceStatus syncStatus;
    syncStatus.needSync = true;
    syncStatus.protocolIdList = { static_cast<ProtocolId>(INT32_999) };
    ctx.manager->HandleSyncResult(deviceKey, 0, SUCCESS, syncStatus);

    TaskRunnerManager::GetInstance().ExecuteAll();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();

    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(ResultCode::PROTOCOL_NEGOTIATION_FAILED, notifiedResult);
    EXPECT_EQ(*retryCount, 0); // terminal: no backoff retry armed
    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(stored.isSynced); // negotiation failure invalidates the cache
    EXPECT_FALSE(stored.isSyncInProgress);
    EXPECT_EQ(stored.lastSyncTimeMs, 0u); // success side effect must not have run
}

// PEER_SYNC_FAILED is the peer's explicit verdict: terminal AND cache-invalidating. A previously
// synced device drops out of the synced set, unlike communication-class failures.
HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_PeerSyncFailedIsTerminalAndInvalidatesCache, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto retryCount = std::make_shared<int>(0);
    bool onResultCalled = false;
    ResultCode notifiedResult = ResultCode::SUCCESS;
    auto physicalStatus = MakePhysicalStatus("device-peer-fail", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, [retryCount]() { (*retryCount)++; });
    entry.isSynced = true;
    entry.isSyncInProgress = true;
    entry.syncWaiters.push_back([&onResultCalled, &notifiedResult](ResultCode resultCode) {
        onResultCalled = true;
        notifiedResult = resultCode;
    });
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    ctx.manager->HandleSyncResult(deviceKey, 0, PEER_SYNC_FAILED, SyncDeviceStatus {});

    TaskRunnerManager::GetInstance().ExecuteAll();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();

    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(ResultCode::PEER_SYNC_FAILED, notifiedResult);
    EXPECT_EQ(*retryCount, 0); // terminal: no backoff retry armed
    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(stored.isSynced); // peer verdict invalidates the cache
    EXPECT_FALSE(stored.isSyncInProgress);
    EXPECT_FALSE(ctx.manager->GetDeviceStatus(deviceKey).has_value());
}

// Communication-class failures (link down / timeout / local transient) say nothing about the
// cached data: the sync bit must survive them, the device stays in the synced set, and the
// backoff schedule keeps working.
HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_CommunicationFailuresKeepCachedSync, TestSize.Level0)
{
    for (ResultCode code : { ResultCode::COMMUNICATION_ERROR, ResultCode::TIMEOUT, ResultCode::GENERAL_ERROR }) {
        auto ctx = SetupTestContext();
        auto retryCount = std::make_shared<int>(0);
        auto physicalStatus = MakePhysicalStatus("device-comm-keep", ChannelId::SOFTBUS, "Device");
        DeviceStatusEntry entry(physicalStatus, [retryCount]() { (*retryCount)++; });
        entry.isSynced = true;
        entry.isSyncInProgress = true;
        ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

        auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
        ctx.manager->HandleSyncResult(deviceKey, 0, code, SyncDeviceStatus {});

        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().EnsureAllTaskExecuted();

        const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
        EXPECT_TRUE(stored.isSynced); // cache kept: the peer never spoke about the data
        EXPECT_FALSE(stored.isSyncInProgress);
        EXPECT_TRUE(ctx.manager->GetDeviceStatus(deviceKey).has_value());
        EXPECT_EQ(*retryCount, 1); // retryable: backoff timer armed and fired once
    }
}

// A round that fails to start (factory null / Start false) is communication-class too: the
// previously synced device must stay online and the failure stays retryable. Uses the event
// entry — an ensure would short-circuit on the synced bit before ever starting a round.
HWTEST_F(DeviceStatusManagerTest, AttachOrStartDeviceSyncStartFailureKeepsCachedSync, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-start-fail-synced", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(deviceKey, SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);

    ctx.manager->ResyncDevice(physicalStatus.physicalDeviceKey);

    TaskRunnerManager::GetInstance().ExecuteAll();

    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(stored.isSynced); // start failure keeps the cached sync state
    EXPECT_FALSE(stored.isSyncInProgress);
    EXPECT_TRUE(ctx.manager->GetDeviceStatus(deviceKey).has_value());
}

HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_NoCommonCapabilities, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.companionCapabilities = { Capability::TOKEN_AUTH };

    auto physicalStatus = MakePhysicalStatus("device-no-cap", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    SyncDeviceStatus syncStatus;
    syncStatus.needSync = true;
    // Use incompatible protocol to trigger sync failure
    syncStatus.protocolIdList = { static_cast<ProtocolId>(INT32_999) };
    syncStatus.capabilityList = { Capability::DELEGATE_AUTH };
    syncStatus.deviceUserName = "user";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;

    ctx.manager->HandleSyncResult(deviceKey, 0, SUCCESS, syncStatus);

    const auto &entry2 = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(entry2.isSynced);
    EXPECT_FALSE(entry2.isSyncInProgress);
}

HWTEST_F(DeviceStatusManagerTest, AttachOrStartDeviceSync_DeviceNotInMap, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey nonExistentKey;
    nonExistentKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    nonExistentKey.deviceId = "non-existent-trigger";

    // An unmonitored device rejects the trigger and reports GENERAL_ERROR on the resident thread.
    // No entry: not adopted (or the channel cannot enumerate it right now) — the condition
    // entry itself is refused with COMMUNICATION_ERROR (section 3.1).
    bool onResultCalled = false;
    ResultCode triggerResult = ResultCode::SUCCESS;
    ASSERT_NO_THROW(
        ctx.manager->EnsureDeviceSynced(nonExistentKey, [&onResultCalled, &triggerResult](ResultCode resultCode) {
            onResultCalled = true;
            triggerResult = resultCode;
        }));
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(ResultCode::COMMUNICATION_ERROR, triggerResult);
}

HWTEST_F(DeviceStatusManagerTest, AttachOrStartDeviceSync_AlreadyInProgress, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-already-syncing", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    entry.inProgressAttemptId = 11;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);

    // The subscription below runs a synchronous ReconcileDevices: keep the channel reporting
    // the device so the pre-emplaced in-flight entry survives it.
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    // The in-flight attach path is demand-gated: park a demand subscription like the real
    // waiter owner (OutboundRequest::BringPeerOnline) does.
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);

    // A second trigger while a sync is running must not start another request: the onResult
    // is attached to the in-progress attempt and stays pending until that attempt settles.
    bool onResultCalled = false;
    ASSERT_NO_THROW(ctx.manager->EnsureDeviceSynced(physicalStatus.physicalDeviceKey,
        [&onResultCalled](ResultCode) { onResultCalled = true; }));
    EXPECT_FALSE(onResultCalled);
    ASSERT_EQ(1u, ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).syncWaiters.size());

    // Settle the parked waiter before teardown: NotifySyncWaiters posts to the resident queue, and
    // the MockGuard destructor draining it later would touch this stack frame after it is gone.
    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    ctx.manager->HandleSyncResult(deviceKey, 11, ResultCode::GENERAL_ERROR, SyncDeviceStatus {});
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(onResultCalled);
}

// Section 3.4, the two-halves rule: the old round's grade is the frozen snapshot; the upgrade
// grade is the settle-time demand. A foreground demand that appears only while the background
// round is already in flight (here: subscribed after the round started) still upgrades — a
// frozen-at-attach flag would never see it.
HWTEST_F(DeviceStatusManagerTest, CoordinatorRejected_UpgradesWhenDemandTurnsForegroundMidFlight, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-midflight-fg", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    entry.inProgressAttemptId = 12;
    entry.inProgressConnectionMode = ConnectionMode::BACKGROUND;
    entry.syncWaiters.push_back([](ResultCode) {});
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // The foreground demand arrives AFTER the background round is on the wire.
    auto foregroundSub = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOREGROUND, nullptr);

    ConnectionMode escalatedMode = ConnectionMode::BACKGROUND;
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(
            Invoke([&escalatedMode](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                escalatedMode = connectionMode;
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    ctx.manager->HandleSyncResult(deviceKey, 12, COORDINATOR_REJECTED, SyncDeviceStatus {});

    EXPECT_EQ(ConnectionMode::FOREGROUND, escalatedMode);
    const auto &escalated = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(escalated.isSyncInProgress);
    EXPECT_EQ(ConnectionMode::FOREGROUND, escalated.inProgressConnectionMode);
    EXPECT_FALSE(escalated.syncWaiters.empty()); // waiters transferred to the escalation round
}

// When the settle-time demand is not foreground, the rejection stands: waiters get the raw
// COORDINATOR_REJECTED code (original-code pass-through), not a downgraded generic error.
HWTEST_F(DeviceStatusManagerTest, CoordinatorRejected_NoForegroundDemandSettlesWaitersWithRawCode, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-no-fg-demand", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    entry.inProgressAttemptId = 14;
    entry.inProgressConnectionMode = ConnectionMode::BACKGROUND;
    bool onResultCalled = false;
    ResultCode notifiedResult = ResultCode::SUCCESS;
    entry.syncWaiters.push_back([&onResultCalled, &notifiedResult](ResultCode resultCode) {
        onResultCalled = true;
        notifiedResult = resultCode;
    });
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // Background-grade demand only: no upgrade branch.
    auto backgroundSub = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::BACKGROUND, nullptr);

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    ctx.manager->HandleSyncResult(deviceKey, 14, COORDINATOR_REJECTED, SyncDeviceStatus {});
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(COORDINATOR_REJECTED, notifiedResult);
    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(stored.isSyncInProgress);
    EXPECT_TRUE(stored.syncWaiters.empty());
}

// The escalation round is a new round: it consumes the pending-resync marker itself, so no
// extra make-up round follows it (the escalated read IS the make-up).
HWTEST_F(DeviceStatusManagerTest, CoordinatorRejected_EscalationRoundConsumesPendingResyncMarker, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-escalate-marker", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    entry.inProgressAttemptId = 16;
    entry.inProgressConnectionMode = ConnectionMode::BACKGROUND;
    entry.pendingResync = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto foregroundSub = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOREGROUND, nullptr);

    uint32_t created = 0;
    ON_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillByDefault(
            Invoke([&created](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                created++;
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    ON_CALL(ctx.guard->GetRequestManager(), Start).WillByDefault(Return(true));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    ctx.manager->HandleSyncResult(deviceKey, 16, COORDINATOR_REJECTED, SyncDeviceStatus {});
    TaskRunnerManager::GetInstance().ExecuteAll();

    // Exactly one escalation round; the marker was consumed by its start, no make-up after it.
    EXPECT_EQ(1u, created);
    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(stored.pendingResync);
    EXPECT_TRUE(stored.isSyncInProgress);
}

HWTEST_F(DeviceStatusManagerTest, AttachOrStartDeviceSync_BringOnlineSkipsAlreadySyncedDevice, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-bring-online-synced", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);
    // The demand is the authorization checked before the synced short-circuit.
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);

    // An ensure on an already-synced device is a pass-through: onResult gets asynchronous
    // SUCCESS with no freshness check, no request is created, and no waiter stays parked.
    bool onResultCalled = false;
    ResultCode triggerResult = ResultCode::GENERAL_ERROR;
    ASSERT_NO_THROW(ctx.manager->EnsureDeviceSynced(physicalStatus.physicalDeviceKey,
        [&onResultCalled, &triggerResult](ResultCode resultCode) {
            onResultCalled = true;
            triggerResult = resultCode;
        }));
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(ResultCode::SUCCESS, triggerResult);
    const auto &syncedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(syncedEntry.isSynced);
    EXPECT_FALSE(syncedEntry.isSyncInProgress);
    EXPECT_TRUE(syncedEntry.syncWaiters.empty());
}

// Settlement table row "already synced (even with a round in flight)": an ensure must not ride a
// forced re-read — it settles SUCCESS immediately while the refresh round keeps running.
HWTEST_F(DeviceStatusManagerTest, EnsureDeviceSynced_ShortCircuitsWhileRefreshInFlight, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-synced-inflight", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.isSyncInProgress = true;
    entry.inProgressAttemptId = 42;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);

    bool onResultCalled = false;
    ResultCode triggerResult = ResultCode::GENERAL_ERROR;
    ctx.manager->EnsureDeviceSynced(physicalStatus.physicalDeviceKey,
        [&onResultCalled, &triggerResult](ResultCode resultCode) {
            onResultCalled = true;
            triggerResult = resultCode;
        });
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(ResultCode::SUCCESS, triggerResult);
    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(stored.isSyncInProgress);    // the in-flight refresh keeps running untouched
    EXPECT_TRUE(stored.syncWaiters.empty()); // the ensure did not park on it
}

// The event entry has no callback: without an entry or without a demand it is ignored (warned),
// never crashing and never settling anything.
HWTEST_F(DeviceStatusManagerTest, ResyncDevice_IgnoredWithoutEntryOrDemand, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey missingKey;
    missingKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    missingKey.deviceId = "resync-missing";
    ASSERT_NO_THROW(ctx.manager->ResyncDevice(missingKey));

    auto physicalStatus = MakePhysicalStatus("device-resync-no-demand", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    auto noneSubscription =
        ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey), SyncDemand::NONE, nullptr);

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);
    ASSERT_NO_THROW(ctx.manager->ResyncDevice(physicalStatus.physicalDeviceKey));
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).pendingResync);
}

// An invalidation event bypasses the already-synced short-circuit: the peer declared the cache
// stale, so a round starts even though the entry is synced.
HWTEST_F(DeviceStatusManagerTest, ResyncDevice_BypassesSyncedShortCircuit, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-resync-synced", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);

    SyncTriggerReason capturedReason = SyncTriggerReason::BACKOFF_RETRY;
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(
            Invoke([&capturedReason](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                capturedReason = triggerReason;
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    ctx.manager->ResyncDevice(physicalStatus.physicalDeviceKey);

    EXPECT_EQ(SyncTriggerReason::RESYNC, capturedReason);
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).isSyncInProgress);
}

// Section 5: a resync event during an in-flight round parks a make-up marker (not a waiter). The
// round settles its own business first, then one make-up round re-reads — the marker is consumed
// by the new round start, and the make-up carries no waiters.
HWTEST_F(DeviceStatusManagerTest, ResyncDuringInFlightRound_StartsMakeUpRoundAfterSettlement, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-make-up", ChannelId::SOFTBUS, "Device");
    // Subscribe while the entry does not exist yet, or the demand-adding registration would
    // start its own round ahead of the DEVICE_ONLINE trigger below.
    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(deviceKey, SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);
    DeviceStatusEntry entry(physicalStatus, []() {});
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    uint32_t created = 0;
    uint64_t lastAttemptId = 0;
    ON_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillByDefault(Invoke(
            [&created, &lastAttemptId](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                created++;
                auto request = std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode,
                    triggerReason, SyncDeviceStatusCallback {});
                lastAttemptId = request->GetRequestId();
                return request;
            }));
    ON_CALL(ctx.guard->GetRequestManager(), Start).WillByDefault(Return(true));

    // Round 1 in flight.
    ctx.manager->AttachOrStartDeviceSync(physicalStatus.physicalDeviceKey, SyncTriggerReason::DEVICE_ONLINE);
    ASSERT_EQ(1u, created);

    // The peer reports a change mid-flight: marker, not waiter.
    ctx.manager->ResyncDevice(physicalStatus.physicalDeviceKey);
    auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    ASSERT_TRUE(stored.pendingResync);
    EXPECT_TRUE(stored.syncWaiters.empty());

    // Round 1 settles successfully: settlement first, then exactly one make-up round.
    ctx.manager->HandleSyncResult(deviceKey, stored.inProgressAttemptId, ResultCode::SUCCESS, SyncDeviceStatus {});
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(2u, created);
    auto &after = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(after.pendingResync);      // consumed by the make-up round start
    EXPECT_TRUE(after.isSyncInProgress);    // the make-up round is on the wire
    EXPECT_TRUE(after.syncWaiters.empty()); // make-up carries no waiters
}

// Demand resolution per section 2.1 of the sync demand model: subscriptions are the single
// source of truth for both gating and mode; NONE contributes nothing and never blocks others;
// FOLLOW_SUBSCRIBE_MODE resolves to the current connection mode; max wins; NONE means no demand.
HWTEST_F(DeviceStatusManagerTest, ResolveSyncDemandLevel_FollowsSubscriptionDemandLevels, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-demand";
    auto deviceKey = MakeDeviceKey(targetKey);
    auto sub = [&ctx, &deviceKey](
                   SyncDemand demand) { return ctx.manager->SubscribeDeviceStatus(deviceKey, demand, nullptr); };

    // No subscription: no demand.
    EXPECT_EQ(SyncDemandLevel::NONE, ctx.manager->ResolveSyncDemandLevel(targetKey));

    // NONE keeps the device adopted but contributes no demand and blocks nothing.
    auto noneSub = sub(SyncDemand::NONE);
    EXPECT_EQ(SyncDemandLevel::NONE, ctx.manager->ResolveSyncDemandLevel(targetKey));

    // FOLLOW_SUBSCRIBE_MODE resolves to the current mode (SUBSCRIBED_ONLY ⇒ BACKGROUND).
    auto followSub = sub(SyncDemand::FOLLOW_SUBSCRIBE_MODE);
    EXPECT_EQ(SyncDemandLevel::BACKGROUND, ctx.manager->ResolveSyncDemandLevel(targetKey));

    // Explicit BACKGROUND / FOREGROUND resolve directly; max wins across subscriptions.
    auto backgroundSub = sub(SyncDemand::BACKGROUND);
    EXPECT_EQ(SyncDemandLevel::BACKGROUND, ctx.manager->ResolveSyncDemandLevel(targetKey));
    {
        auto foregroundSub = sub(SyncDemand::FOREGROUND);
        EXPECT_EQ(SyncDemandLevel::FOREGROUND, ctx.manager->ResolveSyncDemandLevel(targetKey));
    }
    // The foreground subscriber is gone: demand falls back to the remaining max.
    EXPECT_EQ(SyncDemandLevel::BACKGROUND, ctx.manager->ResolveSyncDemandLevel(targetKey));

    // ALL_DEVICES short-circuits BEFORE the per-device max: a NONE subscription must not drag
    // the global foreground mode to NONE, and the mode becomes the global current mode.
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_ALL_DEVICES);
    EXPECT_EQ(SyncDemandLevel::FOREGROUND, ctx.manager->ResolveSyncDemandLevel(targetKey));
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_SUBSCRIBED_ONLY);
    EXPECT_EQ(SyncDemandLevel::BACKGROUND, ctx.manager->ResolveSyncDemandLevel(targetKey));
}

// A NONE subscription never blocks another subscriber's demand (NONE is subscription-level, not
// a device-level ban), and unsubscribing the only demand contributor removes the demand.
HWTEST_F(DeviceStatusManagerTest, ResolveSyncDemandLevel_NoneDoesNotBlockOtherSubscribers, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-demand-none";

    auto deviceKey = MakeDeviceKey(targetKey);
    auto backgroundSub = ctx.manager->SubscribeDeviceStatus(deviceKey, SyncDemand::BACKGROUND, nullptr);
    EXPECT_EQ(SyncDemandLevel::BACKGROUND, ctx.manager->ResolveSyncDemandLevel(targetKey));

    // An unrelated device's subscription contributes nothing to this device.
    PhysicalDeviceKey otherKey = targetKey;
    otherKey.deviceId = "device-demand-other";
    auto otherSub = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(otherKey), SyncDemand::FOREGROUND, nullptr);
    EXPECT_EQ(SyncDemandLevel::BACKGROUND, ctx.manager->ResolveSyncDemandLevel(targetKey));

    backgroundSub.reset();
    EXPECT_EQ(SyncDemandLevel::NONE, ctx.manager->ResolveSyncDemandLevel(targetKey));
}

HWTEST_F(DeviceStatusManagerTest, AttachOrStartDeviceSync_SkippedWhenNoDemand, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-skip-sync", ChannelId::SOFTBUS, "Device");

    // Mock GetAllPhysicalDevices to return the test device, otherwise ReconcileDevices (triggered by
    // SubscribeDeviceStatus) will remove the device from deviceStatusMap_
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = ctx.manager->SubscribeDeviceStatus(deviceKey, SyncDemand::NONE,
        [callbackInvoked](const std::vector<DeviceStatus> &) { *callbackInvoked = true; });

    // Should not create a sync request when there is no demand
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);

    bool onResultCalled = false;
    ResultCode triggerResult = ResultCode::SUCCESS;
    ctx.manager->EnsureDeviceSynced(physicalStatus.physicalDeviceKey,
        [&onResultCalled, &triggerResult](ResultCode resultCode) {
            onResultCalled = true;
            triggerResult = resultCode;
        });

    TaskRunnerManager::GetInstance().ExecuteAll();

    // No sync subscriber: the trigger is refused without a request or a fake sync notification,
    // and the pending onResult is told GENERAL_ERROR. The device stays unsynced.
    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(ResultCode::GENERAL_ERROR, triggerResult);
    EXPECT_FALSE(*callbackInvoked);
    // The refused onResult must not stay parked on the entry for a future attempt.
    const auto &skippedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(skippedEntry.isSynced);
    EXPECT_FALSE(skippedEntry.isSyncInProgress);
    EXPECT_TRUE(skippedEntry.syncWaiters.empty());
}

HWTEST_F(DeviceStatusManagerTest, AttachOrStartDeviceSync_ProceedsWhenDemandPresent, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-proceed-sync", ChannelId::SOFTBUS, "Device");

    // Subscribe while the entry does not exist yet: a demand-adding registration would start
    // its own round and consume the factory expectations below.
    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto subscription = ctx.manager->SubscribeDeviceStatus(deviceKey, SyncDemand::FOLLOW_SUBSCRIBE_MODE,
        [](const std::vector<DeviceStatus> &) {});

    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // Should create a sync request when a demand is present
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(Return(nullptr));                              // Request creation fails, but the call should happen
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0); // Won't start due to null request

    ASSERT_NO_THROW(ctx.manager->AttachOrStartDeviceSync(physicalStatus.physicalDeviceKey, SyncTriggerReason::RESYNC));
}

HWTEST_F(DeviceStatusManagerTest, DeviceOnlineSync_StartedByDefaultOnDeviceAdd, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    auto physicalStatus = MakePhysicalStatus("device-online-sync-default", ChannelId::SOFTBUS, "Device");

    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    SyncTriggerReason capturedReason = SyncTriggerReason::BACKOFF_RETRY;
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(
            Invoke([&capturedReason](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                capturedReason = triggerReason;
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);

    EXPECT_EQ(SyncTriggerReason::DEVICE_ONLINE, capturedReason);
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).isSyncInProgress);
}

// A device re-added by an explicit refresh must still sync, otherwise a narrow/widen round
// trip leaves it unsynced and invisible for good.
HWTEST_F(DeviceStatusManagerTest, DeviceOnlineSync_ExplicitResyncStillReachesAddedDevice, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_ALL_DEVICES;

    auto physicalStatus = MakePhysicalStatus("device-resync-on-add", ChannelId::SOFTBUS, "Device");

    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    SyncTriggerReason capturedReason = SyncTriggerReason::BACKOFF_RETRY;
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(
            Invoke([&capturedReason](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                capturedReason = triggerReason;
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::REEVALUATE_ALL);

    EXPECT_EQ(SyncTriggerReason::EXTERNAL_REFRESH, capturedReason);
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).isSyncInProgress);
}

// Regression: background/foreground round trip. Narrowing prunes the device, widening re-adds it
// through the ADD branch and its refresh trigger syncs it again.
HWTEST_F(DeviceStatusManagerTest, SetSubscribeMode_WidenAfterNarrowResyncsReaddedDevice, TestSize.Level0)
{
    auto ctx = SetupTestContext();

    auto physicalStatus = MakePhysicalStatus("device-narrow-widen", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    std::vector<SyncTriggerReason> reasons;
    ON_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillByDefault(
            Invoke([&reasons](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                reasons.push_back(triggerReason);
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    ON_CALL(ctx.guard->GetRequestManager(), Start).WillByDefault(Return(true));

    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_ALL_DEVICES);
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(1u, ctx.manager->deviceStatusMap_.count(physicalStatus.physicalDeviceKey));
    ASSERT_EQ(1u, reasons.size());

    // Settle the first sync so the entry is no longer in flight and the narrowing may prune it.
    auto &synced = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    synced.isSyncInProgress = false;
    synced.isSynced = true;

    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_SUBSCRIBED_ONLY);
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(0u, ctx.manager->deviceStatusMap_.count(physicalStatus.physicalDeviceKey));

    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_ALL_DEVICES);
    TaskRunnerManager::GetInstance().ExecuteAll();

    ASSERT_EQ(1u, ctx.manager->deviceStatusMap_.count(physicalStatus.physicalDeviceKey));
    ASSERT_EQ(2u, reasons.size());
    EXPECT_EQ(SyncTriggerReason::EXTERNAL_REFRESH, reasons.back());
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).isSyncInProgress);
}

HWTEST_F(DeviceStatusManagerTest, ResolveSyncDemandLevel_PerDeviceSubscriptionsAreIndependent, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-multi-sub";

    PhysicalDeviceKey otherKey;
    otherKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    otherKey.deviceId = "device-other";

    // Target has no demand yet.
    auto sub1 = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey), SyncDemand::NONE, nullptr);
    EXPECT_EQ(SyncDemandLevel::NONE, ctx.manager->ResolveSyncDemandLevel(targetKey));

    // Another device's demand does not leak into the target.
    auto sub2 = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(otherKey), SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);
    EXPECT_EQ(SyncDemandLevel::NONE, ctx.manager->ResolveSyncDemandLevel(targetKey));
    EXPECT_EQ(SyncDemandLevel::BACKGROUND, ctx.manager->ResolveSyncDemandLevel(otherKey));

    // A demand subscription on the target brings it into scope.
    auto sub3 =
        ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey), SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);
    EXPECT_EQ(SyncDemandLevel::BACKGROUND, ctx.manager->ResolveSyncDemandLevel(targetKey));
}

HWTEST_F(DeviceStatusManagerTest, ResolveSyncDemandLevel_GlobalStatusSubscriptionContributesNoDemand, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-global-sub";

    // A global status-only subscription (no deviceKey) is not a demand source.
    auto globalSub = ctx.manager->SubscribeDeviceStatus([](const std::vector<DeviceStatus> &) {});
    EXPECT_EQ(SyncDemandLevel::NONE, ctx.manager->ResolveSyncDemandLevel(targetKey));

    // Only a per-device subscription creates a demand.
    auto specificSub =
        ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey), SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);
    EXPECT_EQ(SyncDemandLevel::BACKGROUND, ctx.manager->ResolveSyncDemandLevel(targetKey));
}

HWTEST_F(DeviceStatusManagerTest, SetSubscribeMode_SameMode, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_SUBSCRIBED_ONLY;
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_SUBSCRIBED_ONLY);
    EXPECT_EQ(SUBSCRIBE_MODE_SUBSCRIBED_ONLY, ctx.manager->currentMode_);
}

HWTEST_F(DeviceStatusManagerTest, SetSubscribeMode_ToManage, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_ALL_DEVICES);
    EXPECT_EQ(SUBSCRIBE_MODE_ALL_DEVICES, ctx.manager->currentMode_);
}

HWTEST_F(DeviceStatusManagerTest, SetTemplateStatusSubscribed_OpensAndClosesWindow, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    constexpr uint64_t steadyTimeMs = 12345;
    ctx.guard->GetTimeKeeper().SetSteadyTime(steadyTimeMs);
    EXPECT_FALSE(ctx.manager->GetTemplateStatusSubscribeTimeMs().has_value());

    ctx.manager->SetTemplateStatusSubscribed(true);
    EXPECT_TRUE(ctx.manager->GetTemplateStatusSubscribeTimeMs().has_value());

    ctx.manager->SetTemplateStatusSubscribed(false);
    EXPECT_FALSE(ctx.manager->GetTemplateStatusSubscribeTimeMs().has_value());
}

// Conditional reevaluation (widening / SDK registration / template window): a synced entry whose
// last sync landed inside the current template window short-circuits — no round.
HWTEST_F(DeviceStatusManagerTest, ConditionalReevaluation_ShortCircuitsSyncedConfirmedEntry, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-reeval-confirmed", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.lastSyncTimeMs = 200;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);

    ctx.guard->GetTimeKeeper().SetSteadyTime(100); // window opens at 100, sync landed at 200
    ctx.manager->SetTemplateStatusSubscribed(true);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);
    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::REEVALUATE_ALL);

    EXPECT_FALSE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).isSyncInProgress);
}

// The third necessity input: a synced entry with no sync landed inside the open window gets one
// reevaluation round — otherwise "synced before subscribing" pins isConfirmed false forever.
HWTEST_F(DeviceStatusManagerTest, ConditionalReevaluation_StartsRoundWhenWindowUnconfirmed, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-reeval-stale", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.lastSyncTimeMs = 100;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);

    ctx.guard->GetTimeKeeper().SetSteadyTime(200); // window opens at 200, sync landed at 100
    ctx.manager->SetTemplateStatusSubscribed(true);

    SyncTriggerReason capturedReason = SyncTriggerReason::BACKOFF_RETRY;
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(
            Invoke([&capturedReason](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                capturedReason = triggerReason;
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    TaskRunnerManager::GetInstance().ExecuteAll(); // window-open reevaluation pass

    EXPECT_EQ(SyncTriggerReason::EXTERNAL_REFRESH, capturedReason);
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).isSyncInProgress);
}

// Without a template window nobody waits for a confirmation: a synced entry short-circuits.
HWTEST_F(DeviceStatusManagerTest, ConditionalReevaluation_NoWindowShortCircuits, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-reeval-nowindow", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.lastSyncTimeMs = 100;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);
    ctx.manager->ReconcileDevices(DeviceReconcilePolicy::REEVALUATE_ALL);

    EXPECT_FALSE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).isSyncInProgress);
}

// SyncDeviceIfNeeded contract pins: one EXTERNAL_REFRESH round fires when the entry has sync
// demand and is either never synced (no window required) or its sync result predates the open
// template window; no demand, in-flight, and in-window entries stop it.
HWTEST_F(DeviceStatusManagerTest, SyncDeviceIfNeeded_TriggersWhenSyncPredatesWindow, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-resync-outdated", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.lastSyncTimeMs = 100;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);
    ctx.manager->templateStatusSubscribeTimeMs_ = 200; // window opens at 200, sync landed at 100

    SyncTriggerReason capturedReason = SyncTriggerReason::BACKOFF_RETRY;
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(
            Invoke([&capturedReason](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                capturedReason = triggerReason;
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    auto &storedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    ctx.manager->SyncDeviceIfNeeded(storedEntry);

    EXPECT_EQ(SyncTriggerReason::EXTERNAL_REFRESH, capturedReason);
    EXPECT_TRUE(storedEntry.isSyncInProgress);
}

HWTEST_F(DeviceStatusManagerTest, SyncDeviceIfNeeded_TriggersWhenNeverSynced, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-sync-never-synced", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);
    // window intentionally unset: never-synced entries start syncing without a template window

    SyncTriggerReason capturedReason = SyncTriggerReason::BACKOFF_RETRY;
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(
            Invoke([&capturedReason](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                capturedReason = triggerReason;
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    auto &storedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    ctx.manager->SyncDeviceIfNeeded(storedEntry);

    EXPECT_EQ(SyncTriggerReason::EXTERNAL_REFRESH, capturedReason);
    EXPECT_TRUE(storedEntry.isSyncInProgress);
}

HWTEST_F(DeviceStatusManagerTest, SyncDeviceIfNeeded_SkippedWhenSyncLandsInWindow, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-resync-in-window", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.lastSyncTimeMs = 200;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);
    ctx.manager->templateStatusSubscribeTimeMs_ = 100; // window opens at 100, sync landed at 200

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);

    auto &storedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    ctx.manager->SyncDeviceIfNeeded(storedEntry);

    EXPECT_FALSE(storedEntry.isSyncInProgress);
}

HWTEST_F(DeviceStatusManagerTest, SyncDeviceIfNeeded_SkippedWhenNoDemand, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-resync-no-demand", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.lastSyncTimeMs = 100;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    ctx.manager->templateStatusSubscribeTimeMs_ = 200;

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);

    auto &storedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    ctx.manager->SyncDeviceIfNeeded(storedEntry);

    EXPECT_FALSE(storedEntry.isSyncInProgress);
}

HWTEST_F(DeviceStatusManagerTest, SyncDeviceIfNeeded_NoDoubleStartWhenSyncInFlight, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-resync-in-flight", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.isSyncInProgress = true;
    entry.lastSyncTimeMs = 100;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);
    ctx.manager->templateStatusSubscribeTimeMs_ = 200;

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);

    auto &storedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    ctx.manager->SyncDeviceIfNeeded(storedEntry);

    EXPECT_TRUE(storedEntry.isSyncInProgress);
}

// The window-open reevaluation is edge-guarded: while the window stays non-empty, later
// SetTemplateStatusSubscribed(true) calls must not re-wake it (section 7).
HWTEST_F(DeviceStatusManagerTest, SetTemplateStatusSubscribed_ReevaluationFiresOnlyOnOpenEdge, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-window-edge", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.lastSyncTimeMs = 100;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);

    uint32_t created = 0;
    ON_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillByDefault(
            Invoke([&created](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                created++;
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    ON_CALL(ctx.guard->GetRequestManager(), Start).WillByDefault(Return(true));

    ctx.guard->GetTimeKeeper().SetSteadyTime(200);
    ctx.manager->SetTemplateStatusSubscribed(true);
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(1u, created); // edge: empty -> non-empty fired one reevaluation round

    // Settle it and re-open inside the still-open window: no further round.
    auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    ctx.manager->HandleSyncResult(deviceKey, stored.inProgressAttemptId, ResultCode::SUCCESS, SyncDeviceStatus {});
    stored.isSynced = true;
    stored.lastSyncTimeMs = 100; // still older than the window start
    TaskRunnerManager::GetInstance().ExecuteAll();

    ctx.manager->SetTemplateStatusSubscribed(true); // window already open: edge-guarded no-op
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(1u, created);
}

// A registration that adds a demand reevaluates an existing unsynced entry immediately: one
// round with a fresh backoff delay, no template-window check (that gate belongs to the
// conditional-reevaluation trio only).
HWTEST_F(DeviceStatusManagerTest, SubscribeDeviceStatus_DemandAddedStartsRoundOnUnsyncedEntry, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-reg-demand", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    SyncTriggerReason capturedReason = SyncTriggerReason::BACKOFF_RETRY;
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(
            Invoke([&capturedReason](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                capturedReason = triggerReason;
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    auto syncSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOLLOW_SUBSCRIBE_MODE, nullptr);

    EXPECT_EQ(SyncTriggerReason::EXTERNAL_REFRESH, capturedReason);
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).isSyncInProgress);
}

// A demand upgrade on a synced entry changes nothing: the grade only affects arbitration
// admission, a re-sync has zero gain (section 6).
HWTEST_F(DeviceStatusManagerTest, SubscribeDeviceStatus_UpgradeOnSyncedEntryDoesNotResync, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-reg-upgrade", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    entry.lastSyncTimeMs = 100;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));
    auto backgroundSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::BACKGROUND, nullptr);

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);
    auto foregroundSubscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(physicalStatus.physicalDeviceKey),
        SyncDemand::FOREGROUND, nullptr);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).isSyncInProgress);
}

// Narrowing the subscribe mode must re-filter the device list: ShouldMonitorDevice reads
// currentMode_, so devices the narrowed scope no longer covers have to be dropped instead of
// staying in the reported list and retrying their sync forever.
HWTEST_F(DeviceStatusManagerTest, SetSubscribeMode_FromManageToAuth, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-narrow-scope", ChannelId::SOFTBUS, "Device");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_ALL_DEVICES);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(1u, ctx.manager->deviceStatusMap_.count(physicalStatus.physicalDeviceKey));

    // Nobody subscribes this device by key, so the narrowed scope no longer covers it.
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_SUBSCRIBED_ONLY);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(SUBSCRIBE_MODE_SUBSCRIBED_ONLY, ctx.manager->currentMode_);
    EXPECT_EQ(0u, ctx.manager->deviceStatusMap_.count(physicalStatus.physicalDeviceKey));
}

// Stale sync completion guard: a completion whose request id does not match the entry's current
// in-progress id (entry rebuilt after the original sync launched, e.g. device went offline then came
// back) must be dropped — a late SUCCESS must not stamp the rebuilt entry with outdated data.
HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_DropsStaleCompletion, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ASSERT_NE(ctx.manager, nullptr);

    auto physicalStatus = MakePhysicalStatus("device-stale-sync", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.inProgressAttemptId = 5; // rebuilt entry's current in-progress id
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    SyncDeviceStatus syncStatus;
    syncStatus.needSync = false;
    syncStatus.deviceUserName = "stale-user";

    // Stale completion (id 3 != 5): dropped, entry untouched.
    ctx.manager->HandleSyncResult(deviceKey, 3, SUCCESS, syncStatus);
    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(stored.isSynced);
    EXPECT_TRUE(stored.deviceUserName.empty());

    // Matching completion (id 5): processed normally.
    ctx.manager->HandleSyncResult(deviceKey, 5, SUCCESS, syncStatus);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(stored.isSynced);
    EXPECT_EQ(stored.deviceUserName, "stale-user");
}

// PEER_SERVICE_NOT_AVAILABLE is terminal: the entry's retry callback must never
// fire (OnSyncAbort cancels any pending backoff retry and clears its state).
HWTEST_F(DeviceStatusManagerTest, HandleSyncResultPeerServiceNotAvailableAbortsRetry, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-peer-na", ChannelId::SOFTBUS, "deviceName");

    auto retryCount = std::make_shared<int>(0);
    DeviceStatusEntry entry(physicalStatus, [retryCount]() { (*retryCount)++; });
    entry.isSyncInProgress = true;
    entry.inProgressAttemptId = 7;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    SyncDeviceStatus syncStatus {};
    ctx.manager->HandleSyncResult(deviceKey, 7, PEER_SERVICE_NOT_AVAILABLE, syncStatus);

    TaskRunnerManager::GetInstance().ExecuteAll();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(*retryCount, 0);
    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(stored.isSynced);
    EXPECT_FALSE(stored.isSyncInProgress);
}

// Regression guard: a generic communication failure still schedules a backoff
// retry (OnSyncFailure), so the peer-no-service branch is the only one suppressed.
HWTEST_F(DeviceStatusManagerTest, HandleSyncResultCommunicationErrorSchedulesRetry, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-comm-err", ChannelId::SOFTBUS, "deviceName");

    auto retryCount = std::make_shared<int>(0);
    DeviceStatusEntry entry(physicalStatus, [retryCount]() { (*retryCount)++; });
    entry.isSyncInProgress = true;
    entry.inProgressAttemptId = 7;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    SyncDeviceStatus syncStatus {};
    ctx.manager->HandleSyncResult(deviceKey, 7, COMMUNICATION_ERROR, syncStatus);

    TaskRunnerManager::GetInstance().ExecuteAll();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(*retryCount, 1);
}

// COORDINATOR_REJECTED is terminal like PEER_SERVICE_NOT_AVAILABLE: the entry's retry callback
// must never fire (OnSyncAbort cancels any pending backoff retry), and an onResult parked for
// the attempt is delivered the raw COORDINATOR_REJECTED code.
HWTEST_F(DeviceStatusManagerTest, HandleSyncResultCoordinatorRejectedAbortsRetryAndNotifiesCallback, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-coord-rejected", ChannelId::SOFTBUS, "deviceName");

    bool onResultCalled = false;
    ResultCode notifiedResult = ResultCode::SUCCESS;
    auto retryCount = std::make_shared<int>(0);
    DeviceStatusEntry entry(physicalStatus, [retryCount]() { (*retryCount)++; });
    entry.isSyncInProgress = true;
    entry.inProgressAttemptId = 7;
    entry.syncWaiters.push_back([&onResultCalled, &notifiedResult](ResultCode resultCode) {
        onResultCalled = true;
        notifiedResult = resultCode;
    });
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    SyncDeviceStatus syncStatus {};
    ctx.manager->HandleSyncResult(deviceKey, 7, COORDINATOR_REJECTED, syncStatus);

    TaskRunnerManager::GetInstance().ExecuteAll();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();

    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(COORDINATOR_REJECTED, notifiedResult);
    EXPECT_EQ(*retryCount, 0);
    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(stored.isSynced);
    EXPECT_FALSE(stored.isSyncInProgress);
    EXPECT_TRUE(stored.syncWaiters.empty());
}

// The coordinator arbitrates by connection mode: a foreground waiter attached to an in-flight
// background attempt must not be terminally failed when that attempt is coordinator-rejected.
// The sync is re-issued once in foreground mode and the moved waiter settles with its result.
HWTEST_F(DeviceStatusManagerTest, HandleSyncResultCoordinatorRejectedEscalatesToForeground, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-coord-escalate", ChannelId::SOFTBUS, "deviceName");
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    bool onResultCalled = false;
    ResultCode notifiedResult = ResultCode::GENERAL_ERROR;
    auto retryCount = std::make_shared<int>(0);
    DeviceStatusEntry entry(physicalStatus, [retryCount]() { (*retryCount)++; });
    entry.isSyncInProgress = true;
    entry.inProgressAttemptId = 21;
    entry.inProgressConnectionMode = ConnectionMode::BACKGROUND;
    entry.syncWaiters.push_back([&onResultCalled, &notifiedResult](ResultCode resultCode) {
        onResultCalled = true;
        notifiedResult = resultCode;
    });
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    ConnectionMode escalatedMode = ConnectionMode::BACKGROUND;
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _))
        .WillOnce(
            Invoke([&escalatedMode](const UserKey &hostUserKey, const DeviceKey &key, ConnectionMode connectionMode,
                       SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback) {
                (void)callback;
                escalatedMode = connectionMode;
                return std::make_shared<HostSyncDeviceStatusRequest>(hostUserKey, key, connectionMode, triggerReason,
                    SyncDeviceStatusCallback {});
            }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    // Mirror BringPeerOnline: the request that parked the waiter also holds the demand
    // subscription. It carries FOREGROUND — the demand that drove the escalation — so the
    // re-issued round resolves to the foreground grade.
    auto subscription = ctx.manager->SubscribeDeviceStatus(deviceKey, SyncDemand::FOREGROUND, nullptr);
    ASSERT_NE(subscription, nullptr);
    SyncDeviceStatus syncStatus {};
    ctx.manager->HandleSyncResult(deviceKey, 21, COORDINATOR_REJECTED, syncStatus);

    // The rejection re-issued the sync in foreground mode; the waiter stays pending, not failed.
    EXPECT_EQ(ConnectionMode::FOREGROUND, escalatedMode);
    EXPECT_FALSE(onResultCalled);
    const auto &escalated = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(escalated.isSyncInProgress);
    EXPECT_EQ(ConnectionMode::FOREGROUND, escalated.inProgressConnectionMode);
    EXPECT_EQ(*retryCount, 0);

    // The escalated attempt settles the moved waiter with its own result.
    ctx.manager->HandleSyncResult(deviceKey, escalated.inProgressAttemptId, SUCCESS, syncStatus);
    TaskRunnerManager::GetInstance().ExecuteAll();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();

    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(ResultCode::SUCCESS, notifiedResult);
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).syncWaiters.empty());
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).isSynced);
}

// The escalation contract is "escalates once": the re-issued foreground attempt has no
// background mode to escalate from, so its own coordinator rejection is terminal — the waiter
// is settled with COORDINATOR_REJECTED and no third attempt is created.
HWTEST_F(DeviceStatusManagerTest, HandleSyncResultCoordinatorRejectedForegroundAttemptIsTerminal, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-coord-fg-terminal", ChannelId::SOFTBUS, "deviceName");

    bool onResultCalled = false;
    ResultCode notifiedResult = ResultCode::SUCCESS;
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    entry.inProgressAttemptId = 31;
    entry.inProgressConnectionMode = ConnectionMode::FOREGROUND;
    entry.syncWaiters.push_back([&onResultCalled, &notifiedResult](ResultCode resultCode) {
        onResultCalled = true;
        notifiedResult = resultCode;
    });
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _, _)).Times(0);

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    SyncDeviceStatus syncStatus {};
    ctx.manager->HandleSyncResult(deviceKey, 31, COORDINATOR_REJECTED, syncStatus);

    TaskRunnerManager::GetInstance().ExecuteAll();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();

    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(COORDINATOR_REJECTED, notifiedResult);
    const auto &stored = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(stored.isSynced);
    EXPECT_FALSE(stored.isSyncInProgress);
    EXPECT_TRUE(stored.syncWaiters.empty());
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
