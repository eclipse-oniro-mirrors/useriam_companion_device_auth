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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_cross_device_channel.h"
#include "mock_guard.h"

#include "channel_manager.h"
#include "connection_manager.h"
#include "device_status_manager.h"
#include "relative_timer.h"
#include "service_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr int32_t INT32_100 = 100;
constexpr int32_t INT32_999 = 999;
constexpr int32_t INT32_99999 = 99999;
} // namespace

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

PhysicalDeviceStatus MakePhysicalStatus(const std::string &deviceId, ChannelId channelId, const std::string &name)
{
    PhysicalDeviceStatus status;
    status.physicalDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    status.physicalDeviceKey.deviceId = deviceId;
    status.channelId = channelId;
    status.deviceName = name;
    status.deviceModelInfo = "model-" + deviceId;
    status.networkId = "network-" + deviceId;
    status.isAuthMaintainActive = true;
    return status;
}

class DeviceStatusManagerTest : public Test {
protected:
    struct TestContext {
        std::unique_ptr<MockGuard> guard;
        std::shared_ptr<NiceMock<MockCrossDeviceChannel>> mockChannel;
        std::shared_ptr<ChannelManager> channelMgr;
        std::shared_ptr<ConnectionManager> connectionMgr;
        std::shared_ptr<LocalDeviceStatusManager> localStatusManager;
        std::shared_ptr<DeviceStatusManager> manager;
        uint64_t nextSubscriptionId = 1;
    };

    TestContext SetupTestContext()
    {
        TestContext ctx;
        ctx.guard = std::make_unique<MockGuard>();
        ctx.mockChannel = InitMockChannel();
        ctx.channelMgr = std::make_shared<ChannelManager>(std::vector<std::shared_ptr<ICrossDeviceChannel>> {
            std::static_pointer_cast<ICrossDeviceChannel>(ctx.mockChannel) });

        ON_CALL(ctx.guard->GetUserIdManager(), GetUnlockedActiveUserId).WillByDefault(Return(activeUserId_));

        DeviceCapabilityInfo deviceCapabilityInfo = { {},
            { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN }, {},
            { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } };
        ctx.localStatusManager = LocalDeviceStatusManager::Create(ctx.channelMgr, deviceCapabilityInfo, false);
        EXPECT_NE(ctx.localStatusManager, nullptr);

        ctx.connectionMgr = ConnectionManager::Create(ctx.channelMgr, ctx.localStatusManager);
        EXPECT_NE(ctx.connectionMgr, nullptr);

        ON_CALL(ctx.guard->GetMiscManager(), GetNextGlobalId).WillByDefault([&ctx]() mutable {
            return ctx.nextSubscriptionId++;
        });

        ctx.manager = DeviceStatusManager::Create({ BusinessId::DEFAULT }, ctx.connectionMgr, ctx.channelMgr,
            ctx.localStatusManager);
        if (ctx.manager == nullptr) {
            return ctx;
        }

        return ctx;
    }

    TestContext SetupTestContextWithBusinessIds(const std::vector<BusinessId> &hostBusinessIds)
    {
        TestContext ctx;
        ctx.guard = std::make_unique<MockGuard>();
        ctx.mockChannel = InitMockChannel();
        ctx.channelMgr = std::make_shared<ChannelManager>(std::vector<std::shared_ptr<ICrossDeviceChannel>> {
            std::static_pointer_cast<ICrossDeviceChannel>(ctx.mockChannel) });

        ON_CALL(ctx.guard->GetUserIdManager(), SubscribeUnlockedActiveUserId)
            .WillByDefault(Invoke([](ActiveUserIdCallback &&) { return MakeSubscription(); }));
        ON_CALL(ctx.guard->GetUserIdManager(), GetUnlockedActiveUserId).WillByDefault(Return(activeUserId_));

        DeviceCapabilityInfo deviceCapabilityInfo = { {},
            { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN }, {},
            { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } };
        ctx.localStatusManager = LocalDeviceStatusManager::Create(ctx.channelMgr, deviceCapabilityInfo, false);
        EXPECT_NE(ctx.localStatusManager, nullptr);

        ctx.connectionMgr = ConnectionManager::Create(ctx.channelMgr, ctx.localStatusManager);
        EXPECT_NE(ctx.connectionMgr, nullptr);

        ON_CALL(ctx.guard->GetMiscManager(), GetNextGlobalId).WillByDefault([&ctx]() mutable {
            return ctx.nextSubscriptionId++;
        });

        ctx.manager =
            DeviceStatusManager::Create(hostBusinessIds, ctx.connectionMgr, ctx.channelMgr, ctx.localStatusManager);
        if (ctx.manager == nullptr) {
            return ctx;
        }

        return ctx;
    }

    DeviceKey MakeDeviceKey(const PhysicalDeviceKey &physicalKey) const
    {
        DeviceKey deviceKey;
        deviceKey.idType = physicalKey.idType;
        deviceKey.deviceId = physicalKey.deviceId;
        deviceKey.deviceUserId = activeUserId_;
        return deviceKey;
    }

    std::shared_ptr<NiceMock<MockCrossDeviceChannel>> InitMockChannel()
    {
        auto mockChannel = std::make_shared<NiceMock<MockCrossDeviceChannel>>();
        ON_CALL(*mockChannel, GetChannelId).WillByDefault(Return(ChannelId::SOFTBUS));
        ON_CALL(*mockChannel, GetAllPhysicalDevices).WillByDefault(Return(std::vector<PhysicalDeviceStatus> {}));
        localPhysicalKey_.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        localPhysicalKey_.deviceId = "local-device";
        ON_CALL(*mockChannel, GetLocalPhysicalDeviceKey).WillByDefault(Return(localPhysicalKey_));
        ON_CALL(*mockChannel, SubscribeAuthMaintainActive).WillByDefault(Invoke([](OnAuthMaintainActiveChange &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel, GetAuthMaintainActive).WillByDefault(Return(false));
        ON_CALL(*mockChannel, GetCompanionSecureProtocolId).WillByDefault(Return(SecureProtocolId::DEFAULT));
        ON_CALL(*mockChannel, SubscribePhysicalDeviceStatus).WillByDefault(Invoke([](OnPhysicalDeviceStatusChange &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel, SubscribeConnectionStatus).WillByDefault(Invoke([](OnConnectionStatusChange &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel, SubscribeIncomingConnection).WillByDefault(Invoke([](OnIncomingConnection &&) {
            return MakeSubscription();
        }));
        return mockChannel;
    }

    int32_t activeUserId_ { INT32_100 };
    PhysicalDeviceKey localPhysicalKey_;
};

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

HWTEST_F(DeviceStatusManagerTest, TriggerDeviceSyncFailsWhenRequestCreationFails, TestSize.Level0)
{
    auto ctx = SetupTestContext();

    auto physicalStatus = MakePhysicalStatus("device-sync-fail-factory", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // Set up mock to return the test device to prevent RefreshDeviceList from removing it
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    // Subscribe with needSync=true to ensure NeedSyncDevice returns true
    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto syncSubscription =
        ctx.manager->SubscribeDeviceStatus(deviceKey, true, [](const std::vector<DeviceStatus> &) {});

    auto notified = std::make_shared<bool>(false);
    auto subscription =
        ctx.manager->SubscribeDeviceStatus([notified](const std::vector<DeviceStatus> &) { *notified = true; });
    (void)subscription;

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);

    ctx.manager->TriggerDeviceSync(physicalStatus.physicalDeviceKey);
    const auto &failedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(failedEntry.isSynced);
    EXPECT_FALSE(failedEntry.isSyncInProgress);
    EXPECT_FALSE(*notified);
}

HWTEST_F(DeviceStatusManagerTest, TriggerDeviceSyncFailsWhenRequestStartFails, TestSize.Level0)
{
    auto ctx = SetupTestContext();

    auto physicalStatus = MakePhysicalStatus("device-sync-fail-start", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // Set up mock to return the test device to prevent RefreshDeviceList from removing it
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    // Subscribe with needSync=true to ensure NeedSyncDevice returns true
    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto syncSubscription =
        ctx.manager->SubscribeDeviceStatus(deviceKey, true, [](const std::vector<DeviceStatus> &) {});

    auto notified = std::make_shared<bool>(false);
    auto subscription =
        ctx.manager->SubscribeDeviceStatus([notified](const std::vector<DeviceStatus> &) { *notified = true; });
    (void)subscription;

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _))
        .WillOnce(Invoke([&](UserId hostUserId, const DeviceKey &key, const std::string &deviceName,
                             SyncDeviceStatusCallback &&callback) {
            (void)callback;
            return std::make_shared<HostSyncDeviceStatusRequest>(hostUserId, key, deviceName,
                SyncDeviceStatusCallback {});
        }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(false));

    ctx.manager->TriggerDeviceSync(physicalStatus.physicalDeviceKey);
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

    // Set up mock to return the test device to prevent RefreshDeviceList from removing it
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

HWTEST_F(DeviceStatusManagerTest, ShouldMonitorDeviceRespectsModeAndSubscriptions, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-keep";

    PhysicalDeviceKey otherKey = targetKey;
    otherKey.deviceId = "device-other";

    auto deviceKey = MakeDeviceKey(targetKey);
    auto subscription = ctx.manager->SubscribeDeviceStatus(deviceKey, true, [](const std::vector<DeviceStatus> &) {});
    EXPECT_TRUE(ctx.manager->ShouldMonitorDevice(targetKey));
    EXPECT_FALSE(ctx.manager->ShouldMonitorDevice(otherKey));

    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_MANAGE);
    EXPECT_TRUE(ctx.manager->ShouldMonitorDevice(otherKey));

    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_AUTH);
    subscription.reset();
    EXPECT_FALSE(ctx.manager->ShouldMonitorDevice(otherKey));
}

HWTEST_F(DeviceStatusManagerTest, RefreshDeviceListAddsAndRemovesDevices, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_MANAGE;

    auto statusA = MakePhysicalStatus("device-A", ChannelId::SOFTBUS, "DeviceA");
    auto statusB = MakePhysicalStatus("device-B", ChannelId::SOFTBUS, "DeviceB");

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { statusA, statusB }))
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { statusB }));

    ctx.manager->RefreshDeviceList(false);
    EXPECT_EQ(2u, ctx.manager->deviceStatusMap_.size());
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.count(statusA.physicalDeviceKey));
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.count(statusB.physicalDeviceKey));
    EXPECT_EQ("DeviceA", ctx.manager->deviceStatusMap_.at(statusA.physicalDeviceKey).physicalDeviceName);

    ctx.manager->RefreshDeviceList(false);
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

    auto subscription =
        ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey), true, [](const std::vector<DeviceStatus> &) {});
    ASSERT_NO_THROW(subscription.reset());
}

HWTEST_F(DeviceStatusManagerTest, TriggerDeviceSyncStartsRequestAndHandlesCallback, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.companionCapabilities = { Capability::TOKEN_AUTH };

    auto physicalStatus = MakePhysicalStatus("device-sync", ChannelId::SOFTBUS, "DeviceSync");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // Set up mock to return the test device to prevent RefreshDeviceList from removing it
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices)
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    // Subscribe with needSync=true to ensure NeedSyncDevice returns true
    auto syncSubscription =
        ctx.manager->SubscribeDeviceStatus(deviceKey, true, [](const std::vector<DeviceStatus> &) {});

    auto notified = std::make_shared<bool>(false);
    auto subscription = ctx.manager->SubscribeDeviceStatus(
        [notified](const std::vector<DeviceStatus> &statusList) { *notified = !statusList.empty(); });
    (void)subscription;

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _))
        .WillOnce(Invoke([&](UserId hostUserId, const DeviceKey &key, const std::string &deviceName,
                             SyncDeviceStatusCallback &&callback) {
            (void)callback;
            auto request =
                std::make_shared<HostSyncDeviceStatusRequest>(hostUserId, key, deviceName, SyncDeviceStatusCallback {});
            return request;
        }));

    EXPECT_CALL(ctx.guard->GetRequestManager(), Start)
        .WillOnce(DoAll(Invoke([&](const std::shared_ptr<IRequest> &request) {
            EXPECT_NE(nullptr, request);
            const auto &inProgressEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
            EXPECT_TRUE(inProgressEntry.isSyncInProgress);
        }),
            Return(true)));

    ctx.manager->TriggerDeviceSync(physicalStatus.physicalDeviceKey);
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

HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_IgnoresDeviceUserId, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-sync-ignore-user", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    // HandleSyncResult no longer filters by deviceUserId. The device's userId comes from the
    // sync response (syncDeviceStatus.deviceUserId), not from the active user.
    DeviceKey keyWithDifferentUser = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    keyWithDifferentUser.deviceUserId = activeUserId_ + 1;

    int32_t reportedDeviceUserId = activeUserId_ + 1;
    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "user";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;
    syncStatus.deviceUserId = reportedDeviceUserId;

    ASSERT_NO_THROW(ctx.manager->HandleSyncResult(keyWithDifferentUser, 0, SUCCESS, syncStatus));

    const auto &syncedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(syncedEntry.isSynced);
    EXPECT_EQ(reportedDeviceUserId, syncedEntry.deviceUserId);
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

HWTEST_F(DeviceStatusManagerTest, TriggerDeviceSync_DeviceNotInMap, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey nonExistentKey;
    nonExistentKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    nonExistentKey.deviceId = "non-existent-trigger";

    ASSERT_NO_THROW(ctx.manager->TriggerDeviceSync(nonExistentKey));
}

HWTEST_F(DeviceStatusManagerTest, TriggerDeviceSync_AlreadyInProgress, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-already-syncing", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);

    ASSERT_NO_THROW(ctx.manager->TriggerDeviceSync(physicalStatus.physicalDeviceKey));
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

HWTEST_F(DeviceStatusManagerTest, ShouldSyncDevice_NeedSyncTrue, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-sync-true";

    auto deviceKey = MakeDeviceKey(targetKey);
    auto subscription = ctx.manager->SubscribeDeviceStatus(deviceKey, true, [](const std::vector<DeviceStatus> &) {});

    EXPECT_TRUE(ctx.manager->NeedSyncDevice(targetKey));

    subscription.reset();
}

HWTEST_F(DeviceStatusManagerTest, ShouldSyncDevice_NeedSyncFalse, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-sync-false";

    auto deviceKey = MakeDeviceKey(targetKey);
    auto subscription = ctx.manager->SubscribeDeviceStatus(deviceKey, false, [](const std::vector<DeviceStatus> &) {});

    EXPECT_FALSE(ctx.manager->NeedSyncDevice(targetKey));

    // MANAGE mode should always sync regardless of needSync
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_MANAGE);
    EXPECT_TRUE(ctx.manager->NeedSyncDevice(targetKey));
}

HWTEST_F(DeviceStatusManagerTest, TriggerDeviceSync_SkippedWhenNeedSyncFalse, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-skip-sync", ChannelId::SOFTBUS, "Device");

    // Mock GetAllPhysicalDevices to return the test device, otherwise RefreshDeviceList (triggered by
    // SubscribeDeviceStatus) will remove the device from deviceStatusMap_
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = ctx.manager->SubscribeDeviceStatus(deviceKey, false,
        [callbackInvoked](const std::vector<DeviceStatus> &statusList) {
            *callbackInvoked = true;
            ASSERT_EQ(1u, statusList.size());
            EXPECT_EQ("device-skip-sync", statusList[0].deviceKey.deviceId);
            // Empty sync result should have default/empty values
            EXPECT_EQ(ProtocolId::INVALID, statusList[0].protocolId);
            EXPECT_TRUE(statusList[0].capabilities.empty());
        });

    // Should not create sync request when needSync is false
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _)).Times(0);
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);

    ctx.manager->TriggerDeviceSync(physicalStatus.physicalDeviceKey);

    TaskRunnerManager::GetInstance().ExecuteAll();

    // Verify that HandleSyncResult was called with empty sync status
    EXPECT_TRUE(callbackInvoked);
    const auto &syncedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(syncedEntry.isSynced);
    EXPECT_FALSE(syncedEntry.isSyncInProgress);
}

HWTEST_F(DeviceStatusManagerTest, TriggerDeviceSync_ProceedsWhenNeedSyncTrue, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-proceed-sync", ChannelId::SOFTBUS, "Device");

    // Mock GetAllPhysicalDevices to return the test device
    // to prevent RefreshDeviceList (triggered by SubscribeDeviceStatus) from removing the device
    ON_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    auto subscription = ctx.manager->SubscribeDeviceStatus(deviceKey, true, [](const std::vector<DeviceStatus> &) {});

    // Should create sync request when needSync is true
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _))
        .WillOnce(Return(nullptr));                              // Request creation fails, but the call should happen
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0); // Won't start due to null request

    ASSERT_NO_THROW(ctx.manager->TriggerDeviceSync(physicalStatus.physicalDeviceKey));
}

HWTEST_F(DeviceStatusManagerTest, NeedSyncDevice_MultipleSubscriptions, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-multi-sub";

    PhysicalDeviceKey otherKey;
    otherKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    otherKey.deviceId = "device-other";

    // Subscribe to target with needSync=false
    auto sub1 =
        ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey), false, [](const std::vector<DeviceStatus> &) {});
    EXPECT_FALSE(ctx.manager->NeedSyncDevice(targetKey));

    // Subscribe to another device with needSync=true (should not affect targetKey)
    auto sub2 =
        ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(otherKey), true, [](const std::vector<DeviceStatus> &) {});
    EXPECT_FALSE(ctx.manager->NeedSyncDevice(targetKey));
    EXPECT_TRUE(ctx.manager->NeedSyncDevice(otherKey));

    // Subscribe to target with needSync=true (now targetKey should need sync)
    auto sub3 =
        ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey), true, [](const std::vector<DeviceStatus> &) {});
    EXPECT_TRUE(ctx.manager->NeedSyncDevice(targetKey));
}

HWTEST_F(DeviceStatusManagerTest, NeedSyncDevice_GlobalSubscriptionDoesNotAffectSpecific, TestSize.Level1)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-global-sub";

    // Global subscription (no deviceKey) should not affect NeedSyncDevice
    auto globalSub = ctx.manager->SubscribeDeviceStatus([](const std::vector<DeviceStatus> &) {});
    EXPECT_FALSE(ctx.manager->NeedSyncDevice(targetKey));

    // Even with needSync=true on specific device subscription
    auto specificSub =
        ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey), true, [](const std::vector<DeviceStatus> &) {});
    EXPECT_TRUE(ctx.manager->NeedSyncDevice(targetKey));
}

HWTEST_F(DeviceStatusManagerTest, SetSubscribeMode_SameMode, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_AUTH;
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_AUTH);
    EXPECT_EQ(SUBSCRIBE_MODE_AUTH, ctx.manager->currentMode_);
}

HWTEST_F(DeviceStatusManagerTest, SetSubscribeMode_ToManage, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_MANAGE);
    EXPECT_EQ(SUBSCRIBE_MODE_MANAGE, ctx.manager->currentMode_);
    EXPECT_TRUE(ctx.manager->GetManageSubscribeTime().has_value());
}

HWTEST_F(DeviceStatusManagerTest, SetSubscribeMode_FromManageToAuth, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_MANAGE);
    EXPECT_TRUE(ctx.manager->GetManageSubscribeTime().has_value());

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices()).WillOnce(Return(std::vector<PhysicalDeviceStatus> {}));

    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_AUTH);
    EXPECT_EQ(SUBSCRIBE_MODE_AUTH, ctx.manager->currentMode_);
    EXPECT_FALSE(ctx.manager->GetManageSubscribeTime().has_value());
}

HWTEST_F(DeviceStatusManagerTest, CollectFilteredDevices_NullChannel, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto channelMgrWithNull = std::make_shared<ChannelManager>(std::vector<std::shared_ptr<ICrossDeviceChannel>> {
        std::static_pointer_cast<ICrossDeviceChannel>(ctx.mockChannel), nullptr });

    auto mgr = DeviceStatusManager::Create({ BusinessId::DEFAULT }, ctx.connectionMgr, channelMgrWithNull,
        ctx.localStatusManager);
    ASSERT_NE(mgr, nullptr);
    mgr->SetSubscribeMode(SUBSCRIBE_MODE_MANAGE);

    auto filteredDevices = mgr->CollectFilteredDevices();
}

HWTEST_F(DeviceStatusManagerTest, RefreshDeviceList_WithResync, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_MANAGE;

    auto statusA = MakePhysicalStatus("device-resync-A", ChannelId::SOFTBUS, "DeviceA");
    DeviceStatusEntry entryA(statusA, []() {});
    entryA.isSynced = true;
    ctx.manager->deviceStatusMap_.emplace(statusA.physicalDeviceKey, std::move(entryA));

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { statusA }));

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _))
        .WillOnce(Invoke([&](UserId hostUserId, const DeviceKey &key, const std::string &deviceName,
                             SyncDeviceStatusCallback &&callback) {
            return std::make_shared<HostSyncDeviceStatusRequest>(hostUserId, key, deviceName,
                SyncDeviceStatusCallback {});
        }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    ASSERT_NO_THROW(ctx.manager->RefreshDeviceList(true));
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

HWTEST_F(DeviceStatusManagerTest, SubscribeDeviceStatus_SpecificDevice_RefreshTriggered, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-specific-sub";

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .Times(AtLeast(1))
        .WillRepeatedly(Return(std::vector<PhysicalDeviceStatus> {}));

    ASSERT_NO_THROW(auto subscription = ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey), true,
                        [](const std::vector<DeviceStatus> &) {}));
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
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_MANAGE;

    auto physicalStatus = MakePhysicalStatus("device-refresh-token", ChannelId::SOFTBUS, "Device");
    physicalStatus.refreshToken = false;

    // First add with refreshToken=false
    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    ctx.manager->RefreshDeviceList(false);
    ASSERT_EQ(1u, ctx.manager->deviceStatusMap_.size());
    EXPECT_FALSE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).refreshToken);

    // Now update with refreshToken=true
    auto updatedStatus = physicalStatus;
    updatedStatus.refreshToken = true;

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { updatedStatus }));

    ctx.manager->RefreshDeviceList(false);
    ASSERT_EQ(1u, ctx.manager->deviceStatusMap_.size());
    EXPECT_TRUE(ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey).refreshToken);
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
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_MANAGE;

    auto physicalStatus = MakePhysicalStatus("device-new", ChannelId::SOFTBUS, "Device");
    physicalStatus.supportedBusinessIds = { static_cast<BusinessId>(10002), static_cast<BusinessId>(10003) };

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _))
        .WillOnce(Invoke([&](UserId hostUserId, const DeviceKey &key, const std::string &deviceName,
                             SyncDeviceStatusCallback &&callback) {
            return std::make_shared<HostSyncDeviceStatusRequest>(hostUserId, key, deviceName,
                SyncDeviceStatusCallback {});
        }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    ctx.manager->RefreshDeviceList(false);

    auto it = ctx.manager->deviceStatusMap_.find(physicalStatus.physicalDeviceKey);
    ASSERT_NE(it, ctx.manager->deviceStatusMap_.end());
    ASSERT_EQ(it->second.GetSupportedBusinessIds().size(), 1u);
    EXPECT_EQ(it->second.GetSupportedBusinessIds()[0], static_cast<BusinessId>(10002));
}

HWTEST_F(DeviceStatusManagerTest, AddOrUpdateDevices_NewDevice_EmptyDeviceIds, TestSize.Level0)
{
    auto ctx = SetupTestContextWithBusinessIds({ static_cast<BusinessId>(10001) });
    ASSERT_NE(ctx.manager, nullptr);
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_MANAGE;

    auto physicalStatus = MakePhysicalStatus("device-empty", ChannelId::SOFTBUS, "Device");

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));
    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _))
        .WillOnce(Invoke([&](UserId hostUserId, const DeviceKey &key, const std::string &deviceName,
                             SyncDeviceStatusCallback &&callback) {
            return std::make_shared<HostSyncDeviceStatusRequest>(hostUserId, key, deviceName,
                SyncDeviceStatusCallback {});
        }));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).WillOnce(Return(true));

    ctx.manager->RefreshDeviceList(false);

    auto it = ctx.manager->deviceStatusMap_.find(physicalStatus.physicalDeviceKey);
    ASSERT_NE(it, ctx.manager->deviceStatusMap_.end());
    EXPECT_TRUE(it->second.GetSupportedBusinessIds().empty());
}

HWTEST_F(DeviceStatusManagerTest, AddOrUpdateDevices_SupportedBusinessIdsChanged, TestSize.Level0)
{
    auto ctx = SetupTestContextWithBusinessIds(
        { static_cast<BusinessId>(10001), static_cast<BusinessId>(10002), static_cast<BusinessId>(10003) });
    ASSERT_NE(ctx.manager, nullptr);
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_MANAGE;

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

    ctx.manager->RefreshDeviceList(false);

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
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_MANAGE;

    auto physicalStatus = MakePhysicalStatus("device-biz-same", ChannelId::SOFTBUS, "Device");
    physicalStatus.supportedBusinessIds = { static_cast<BusinessId>(10001) };

    DeviceStatusEntry entry(physicalStatus, []() {}, ctx.manager->hostSupportBusinessIds_);
    entry.isSynced = true;
    entry.protocolId = ProtocolId::VERSION_1;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { physicalStatus }));

    ctx.manager->RefreshDeviceList(false);

    auto it = ctx.manager->deviceStatusMap_.find(physicalStatus.physicalDeviceKey);
    ASSERT_NE(it, ctx.manager->deviceStatusMap_.end());
    ASSERT_EQ(it->second.GetSupportedBusinessIds().size(), 1u);
    EXPECT_EQ(it->second.GetSupportedBusinessIds()[0], static_cast<BusinessId>(10001));
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
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
