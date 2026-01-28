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

#include "channel_manager.h"
#include "connection_manager.h"
#include "device_status_manager.h"
#include "mock_cross_device_channel.h"
#include "mock_guard.h"
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

        ON_CALL(ctx.guard->GetUserIdManager(), SubscribeActiveUserId).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
            return MakeSubscription();
        }));
        ON_CALL(ctx.guard->GetUserIdManager(), GetActiveUserId).WillByDefault(Return(activeUserId_));

        ctx.localStatusManager = LocalDeviceStatusManager::Create(ctx.channelMgr);
        EXPECT_NE(ctx.localStatusManager, nullptr);

        ctx.connectionMgr = ConnectionManager::Create(ctx.channelMgr, ctx.localStatusManager);
        EXPECT_NE(ctx.connectionMgr, nullptr);

        ON_CALL(ctx.guard->GetMiscManager(), GetNextGlobalId).WillByDefault([&ctx]() mutable {
            return ctx.nextSubscriptionId++;
        });

        ctx.manager = DeviceStatusManager::Create(ctx.connectionMgr, ctx.channelMgr, ctx.localStatusManager);
        if (ctx.manager == nullptr) {
            return ctx;
        }
        ctx.manager->activeUserId_ = activeUserId_;

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
    ctx.localStatusManager->profile_.capabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };

    bool callbackInvoked = false;
    size_t callbackCount = 0;
    auto subscription = ctx.manager->SubscribeDeviceStatus([&](const std::vector<DeviceStatus> &statusList) {
        callbackInvoked = true;
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
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "tester";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;

    ctx.manager->HandleSyncResult(deviceKey, SUCCESS, syncStatus);

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

HWTEST_F(DeviceStatusManagerTest, TriggerDeviceSyncFailsWhenRequestCreationFails, TestSize.Level0)
{
    auto ctx = SetupTestContext();

    auto physicalStatus = MakePhysicalStatus("device-sync-fail-factory", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    bool notified = false;
    auto subscription = ctx.manager->SubscribeDeviceStatus([&](const std::vector<DeviceStatus> &) { notified = true; });
    (void)subscription;

    EXPECT_CALL(ctx.guard->GetRequestFactory(), CreateHostSyncDeviceStatusRequest(_, _, _, _))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(ctx.guard->GetRequestManager(), Start).Times(0);

    ctx.manager->TriggerDeviceSync(physicalStatus.physicalDeviceKey);
    const auto &failedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(failedEntry.isSynced);
    EXPECT_FALSE(failedEntry.isSyncInProgress);
    EXPECT_FALSE(notified);
}

HWTEST_F(DeviceStatusManagerTest, TriggerDeviceSyncFailsWhenRequestStartFails, TestSize.Level0)
{
    auto ctx = SetupTestContext();

    auto physicalStatus = MakePhysicalStatus("device-sync-fail-start", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    bool notified = false;
    auto subscription = ctx.manager->SubscribeDeviceStatus([&](const std::vector<DeviceStatus> &) { notified = true; });
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
    EXPECT_FALSE(notified);
}

HWTEST_F(DeviceStatusManagerTest, HandleSyncResultFailureMarksEntryAndSkipsNotification, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-2", ChannelId::SOFTBUS, "deviceName");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    bool callbackInvoked = false;
    auto subscription = ctx.manager->SubscribeDeviceStatus([&](const std::vector<DeviceStatus> &statusList) {
        (void)statusList;
        callbackInvoked = true;
    });
    (void)subscription;

    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "tester";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;
    ctx.manager->HandleSyncResult(deviceKey, GENERAL_ERROR, syncStatus);

    EXPECT_FALSE(callbackInvoked);
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
    auto subscription = ctx.manager->SubscribeDeviceStatus(deviceKey, [](const std::vector<DeviceStatus> &) {});
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
    EXPECT_EQ("DeviceA", ctx.manager->deviceStatusMap_.at(statusA.physicalDeviceKey).deviceName);

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
        ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey), [](const std::vector<DeviceStatus> &) {});
    subscription.reset();
}

HWTEST_F(DeviceStatusManagerTest, TriggerDeviceSyncStartsRequestAndHandlesCallback, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.capabilities = { Capability::TOKEN_AUTH };

    auto physicalStatus = MakePhysicalStatus("device-sync", ChannelId::SOFTBUS, "DeviceSync");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    bool notified = false;
    auto subscription = ctx.manager->SubscribeDeviceStatus(
        [&](const std::vector<DeviceStatus> &statusList) { notified = !statusList.empty(); });
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
    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "remote-user";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;
    ctx.manager->HandleSyncResult(deviceKey, SUCCESS, syncStatus);

    const auto &storedEntry = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(storedEntry.isSynced);
    EXPECT_FALSE(storedEntry.isSyncInProgress);
    EXPECT_EQ("remote-user", storedEntry.deviceUserName);
    EXPECT_TRUE(notified);
}

HWTEST_F(DeviceStatusManagerTest, GetDeviceStatus_WrongUserId, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-wrong-user", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSynced = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    DeviceKey wrongUserKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    wrongUserKey.deviceUserId = activeUserId_ + 1;

    auto result = ctx.manager->GetDeviceStatus(wrongUserKey);
    EXPECT_FALSE(result.has_value());
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

HWTEST_F(DeviceStatusManagerTest, GetChannelIdByDeviceKey_WrongUserId, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-channel-wrong-user", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    DeviceKey wrongUserKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    wrongUserKey.deviceUserId = activeUserId_ + 1;

    auto result = ctx.manager->GetChannelIdByDeviceKey(wrongUserKey);
    EXPECT_FALSE(result.has_value());
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

HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_WrongUserId, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto physicalStatus = MakePhysicalStatus("device-sync-wrong-user", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    DeviceKey wrongUserKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);
    wrongUserKey.deviceUserId = activeUserId_ + 1;

    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "user";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;

    ctx.manager->HandleSyncResult(wrongUserKey, SUCCESS, syncStatus);
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

    ctx.manager->HandleSyncResult(nonExistentKey, SUCCESS, syncStatus);
}

HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_NoCommonProtocol, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.capabilities = { Capability::TOKEN_AUTH };

    auto physicalStatus = MakePhysicalStatus("device-no-protocol", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { static_cast<ProtocolId>(INT32_999) };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "user";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;

    ctx.manager->HandleSyncResult(deviceKey, SUCCESS, syncStatus);

    const auto &entry2 = ctx.manager->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(entry2.isSynced);
    EXPECT_FALSE(entry2.isSyncInProgress);
}

HWTEST_F(DeviceStatusManagerTest, HandleSyncResult_NoCommonCapabilities, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.capabilities = { Capability::TOKEN_AUTH };

    auto physicalStatus = MakePhysicalStatus("device-no-cap", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus, []() {});
    entry.isSyncInProgress = true;
    ctx.manager->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, std::move(entry));

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::DELEGATE_AUTH };
    syncStatus.deviceUserName = "user";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;

    ctx.manager->HandleSyncResult(deviceKey, SUCCESS, syncStatus);

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

    ctx.manager->TriggerDeviceSync(nonExistentKey);
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

    ctx.manager->TriggerDeviceSync(physicalStatus.physicalDeviceKey);
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

HWTEST_F(DeviceStatusManagerTest, SetSubscribeMode_SameMode, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->currentMode_ = SUBSCRIBE_MODE_AUTH;
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_AUTH);
    EXPECT_EQ(SUBSCRIBE_MODE_AUTH, ctx.manager->GetCurrentMode());
}

HWTEST_F(DeviceStatusManagerTest, SetSubscribeMode_ToManage, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_MANAGE);
    EXPECT_EQ(SUBSCRIBE_MODE_MANAGE, ctx.manager->GetCurrentMode());
    EXPECT_TRUE(ctx.manager->GetManageSubscribeTime().has_value());
}

HWTEST_F(DeviceStatusManagerTest, SetSubscribeMode_FromManageToAuth, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_MANAGE);
    EXPECT_TRUE(ctx.manager->GetManageSubscribeTime().has_value());

    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices()).WillOnce(Return(std::vector<PhysicalDeviceStatus> {}));

    ctx.manager->SetSubscribeMode(SUBSCRIBE_MODE_AUTH);
    EXPECT_EQ(SUBSCRIBE_MODE_AUTH, ctx.manager->GetCurrentMode());
    EXPECT_FALSE(ctx.manager->GetManageSubscribeTime().has_value());
}

HWTEST_F(DeviceStatusManagerTest, HandleUserIdChange_SameUserId, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    int32_t originalUserId = ctx.manager->activeUserId_;
    ctx.manager->HandleUserIdChange(originalUserId);
    EXPECT_EQ(originalUserId, ctx.manager->activeUserId_);
}

HWTEST_F(DeviceStatusManagerTest, HandleUserIdChange_DifferentUserId, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices()).WillOnce(Return(std::vector<PhysicalDeviceStatus> {}));

    int32_t newUserId = activeUserId_ + INT32_100;
    ctx.manager->HandleUserIdChange(newUserId);
    EXPECT_EQ(newUserId, ctx.manager->activeUserId_);
}

HWTEST_F(DeviceStatusManagerTest, CollectFilteredDevices_NullChannel, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    auto channelMgrWithNull = std::make_shared<ChannelManager>(std::vector<std::shared_ptr<ICrossDeviceChannel>> {
        std::static_pointer_cast<ICrossDeviceChannel>(ctx.mockChannel), nullptr });

    auto mgr = DeviceStatusManager::Create(ctx.connectionMgr, channelMgrWithNull, ctx.localStatusManager);
    ASSERT_NE(mgr, nullptr);
    mgr->activeUserId_ = activeUserId_;
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

    ctx.manager->RefreshDeviceList(true);
}

HWTEST_F(DeviceStatusManagerTest, HandleChannelDeviceStatusChange, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    EXPECT_CALL(*ctx.mockChannel, GetAllPhysicalDevices()).WillOnce(Return(std::vector<PhysicalDeviceStatus> {}));

    ctx.manager->HandleChannelDeviceStatusChange(ChannelId::SOFTBUS, std::vector<PhysicalDeviceStatus> {});
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

HWTEST_F(DeviceStatusManagerTest, NegotiateCapabilities_MultipleCapabilities, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.capabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH,
        Capability::INVALID };

    std::vector<Capability> remoteCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH };
    auto result = ctx.manager->NegotiateCapabilities(remoteCapabilities);

    EXPECT_EQ(2u, result.size());
    EXPECT_TRUE(std::find(result.begin(), result.end(), Capability::DELEGATE_AUTH) != result.end());
    EXPECT_TRUE(std::find(result.begin(), result.end(), Capability::TOKEN_AUTH) != result.end());
}

HWTEST_F(DeviceStatusManagerTest, NegotiateCapabilities_NoCommon, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.capabilities = { Capability::TOKEN_AUTH };

    std::vector<Capability> remoteCapabilities = { Capability::DELEGATE_AUTH };
    auto result = ctx.manager->NegotiateCapabilities(remoteCapabilities);

    EXPECT_EQ(0u, result.size());
}

HWTEST_F(DeviceStatusManagerTest, GetAllDeviceStatus_MultipleSynced, TestSize.Level0)
{
    auto ctx = SetupTestContext();
    ctx.localStatusManager->profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.protocols = { ProtocolId::VERSION_1 };
    ctx.localStatusManager->profile_.capabilities = { Capability::TOKEN_AUTH };

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

    auto subscription =
        ctx.manager->SubscribeDeviceStatus(MakeDeviceKey(targetKey), [](const std::vector<DeviceStatus> &) {});
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

    ctx.manager->NotifySubscribers();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
