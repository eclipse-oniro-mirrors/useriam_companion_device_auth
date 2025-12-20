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

#include "device_status_manager.h"
#include "service_common.h"

#include "connection_manager.h"

#include "mock_active_user_id_manager.h"
#include "mock_companion_manager.h"
#include "mock_cross_device_channel.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"

#include "channel_manager.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

using namespace testing;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

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
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        // Register all mock objects in SingletonManager
        auto activeUserMgr =
            std::shared_ptr<IActiveUserIdManager>(&activeUserIdManager_, [](IActiveUserIdManager *) {});
        SingletonManager::GetInstance().SetActiveUserIdManager(activeUserMgr);

        auto misc = std::shared_ptr<IMiscManager>(&miscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(misc);

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&crossDeviceCommMgr_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestMgr = std::shared_ptr<IRequestManager>(&requestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto requestFactory = std::shared_ptr<IRequestFactory>(&requestFactory_, [](IRequestFactory *) {});
        SingletonManager::GetInstance().SetRequestFactory(requestFactory);

        auto companionMgr = std::shared_ptr<ICompanionManager>(&companionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&securityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        mockChannel_ = InitMockChannel();
        channelMgr_ = std::make_shared<ChannelManager>(std::vector<std::shared_ptr<ICrossDeviceChannel>> {
            std::static_pointer_cast<ICrossDeviceChannel>(mockChannel_) });
        ON_CALL(activeUserIdManager_, SubscribeActiveUserId).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
            return MakeSubscription();
        }));
        ON_CALL(activeUserIdManager_, GetActiveUserId).WillByDefault(Return(activeUserId_));
        localStatusManager_ = LocalDeviceStatusManager::Create(channelMgr_);
        ASSERT_NE(localStatusManager_, nullptr);
        connectionMgr_ = ConnectionManager::Create(channelMgr_, localStatusManager_);
        ASSERT_NE(connectionMgr_, nullptr);
        ON_CALL(miscManager_, GetNextGlobalId).WillByDefault([this]() mutable { return nextSubscriptionId_++; });
        manager_ = DeviceStatusManager::Create(connectionMgr_, channelMgr_, localStatusManager_);
        ASSERT_NE(manager_, nullptr);
        manager_->activeUserId_ = activeUserId_;
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

    DeviceKey MakeDeviceKey(const PhysicalDeviceKey &physicalKey) const
    {
        DeviceKey deviceKey;
        deviceKey.idType = physicalKey.idType;
        deviceKey.deviceId = physicalKey.deviceId;
        deviceKey.deviceUserId = activeUserId_;
        return deviceKey;
    }

protected:
    int32_t activeUserId_ { 100 };
    int32_t nextSubscriptionId_ { 1 };
    NiceMock<MockMiscManager> miscManager_;
    NiceMock<MockActiveUserIdManager> activeUserIdManager_;
    NiceMock<MockRequestFactory> requestFactory_;
    NiceMock<MockRequestManager> requestManager_;
    NiceMock<MockCrossDeviceCommManager> crossDeviceCommMgr_;
    NiceMock<MockCompanionManager> companionManager_;
    NiceMock<MockSecurityAgent> securityAgent_;
    PhysicalDeviceKey localPhysicalKey_;
    std::shared_ptr<NiceMock<MockCrossDeviceChannel>> mockChannel_;
    std::shared_ptr<ChannelManager> channelMgr_;
    std::shared_ptr<ConnectionManager> connectionMgr_;
    std::shared_ptr<LocalDeviceStatusManager> localStatusManager_;
    std::shared_ptr<DeviceStatusManager> manager_;

private:
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
        ON_CALL(*mockChannel, GetcompanionSecureProtocolId).WillByDefault(Return(SecureProtocolId::DEFAULT));
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
};

TEST_F(DeviceStatusManagerTest, HandleSyncResultSuccessPropagatesNegotiatedStatus)
{
    LocalDeviceStatus localStatus;
    localStatus.protocolPriorityList = { ProtocolId::VERSION_1 };
    localStatus.protocols = { ProtocolId::VERSION_1 };
    localStatus.capabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };
    localStatusManager_->localDeviceStatus_ = localStatus;

    bool callbackInvoked = false;
    size_t callbackCount = 0;
    auto subscription = manager_->SubscribeDeviceStatus([&](const std::vector<DeviceStatus> &statusList) {
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
    DeviceStatusEntry entry(physicalStatus);
    entry.isSyncInProgress = true;
    manager_->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, entry);

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "tester";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;

    manager_->HandleSyncResult(deviceKey, SUCCESS, syncStatus);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
    EXPECT_EQ(1u, callbackCount);
    auto result = manager_->GetDeviceStatus(deviceKey);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(ChannelId::SOFTBUS, result->channelId);
    const auto &storedEntry = manager_->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(storedEntry.isSynced);
    EXPECT_FALSE(storedEntry.isSyncInProgress);
    auto allDevices = manager_->GetAllDeviceStatus();
    ASSERT_EQ(1u, allDevices.size());
    auto channelId = manager_->GetChannelIdByDeviceKey(deviceKey);
    ASSERT_TRUE(channelId.has_value());
    EXPECT_EQ(ChannelId::SOFTBUS, channelId.value());
}

TEST_F(DeviceStatusManagerTest, TriggerDeviceSyncFailsWhenRequestCreationFails)
{
    auto physicalStatus = MakePhysicalStatus("device-sync-fail-factory", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus);
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    manager_->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, entry);

    bool notified = false;
    auto subscription = manager_->SubscribeDeviceStatus([&](const std::vector<DeviceStatus> &) { notified = true; });
    (void)subscription;

    EXPECT_CALL(requestFactory_, CreateHostSyncDeviceStatusRequest(_, _, _, _)).WillOnce(Return(nullptr));
    EXPECT_CALL(requestManager_, Start).Times(0);

    manager_->TriggerDeviceSync(physicalStatus.physicalDeviceKey);
    const auto &failedEntry = manager_->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(failedEntry.isSynced);
    EXPECT_FALSE(failedEntry.isSyncInProgress);
    EXPECT_FALSE(notified);
}

TEST_F(DeviceStatusManagerTest, TriggerDeviceSyncFailsWhenRequestStartFails)
{
    auto physicalStatus = MakePhysicalStatus("device-sync-fail-start", ChannelId::SOFTBUS, "Device");
    DeviceStatusEntry entry(physicalStatus);
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    manager_->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, entry);

    bool notified = false;
    auto subscription = manager_->SubscribeDeviceStatus([&](const std::vector<DeviceStatus> &) { notified = true; });
    (void)subscription;

    EXPECT_CALL(requestFactory_, CreateHostSyncDeviceStatusRequest(_, _, _, _))
        .WillOnce(Invoke([&](UserId hostUserId, const DeviceKey &key, const std::string &deviceName,
                             SyncDeviceStatusCallback &&callback) {
            (void)callback;
            return std::make_shared<HostSyncDeviceStatusRequest>(hostUserId, key, deviceName,
                SyncDeviceStatusCallback {});
        }));
    EXPECT_CALL(requestManager_, Start).WillOnce(Return(false));

    manager_->TriggerDeviceSync(physicalStatus.physicalDeviceKey);
    const auto &failedEntry2 = manager_->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(failedEntry2.isSynced);
    EXPECT_FALSE(failedEntry2.isSyncInProgress);
    EXPECT_FALSE(notified);
}

TEST_F(DeviceStatusManagerTest, HandleSyncResultFailureMarksEntryAndSkipsNotification)
{
    auto physicalStatus = MakePhysicalStatus("device-2", ChannelId::SOFTBUS, "deviceName");
    DeviceStatusEntry entry(physicalStatus);
    entry.isSyncInProgress = true;
    manager_->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, entry);

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    bool callbackInvoked = false;
    auto subscription = manager_->SubscribeDeviceStatus([&](const std::vector<DeviceStatus> &statusList) {
        (void)statusList;
        callbackInvoked = true;
    });
    (void)subscription;

    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "tester";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;
    manager_->HandleSyncResult(deviceKey, GENERAL_ERROR, syncStatus);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackInvoked);
    const auto &failedEntry3 = manager_->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_FALSE(failedEntry3.isSynced);
    EXPECT_FALSE(failedEntry3.isSyncInProgress);
    EXPECT_FALSE(manager_->GetDeviceStatus(deviceKey).has_value());
}

TEST_F(DeviceStatusManagerTest, ShouldMonitorDeviceRespectsModeAndSubscriptions)
{
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-keep";

    PhysicalDeviceKey otherKey = targetKey;
    otherKey.deviceId = "device-other";

    auto deviceKey = MakeDeviceKey(targetKey);
    auto subscription = manager_->SubscribeDeviceStatus(deviceKey, [](const std::vector<DeviceStatus> &) {});
    EXPECT_TRUE(manager_->ShouldMonitorDevice(targetKey));
    EXPECT_FALSE(manager_->ShouldMonitorDevice(otherKey));

    manager_->SetSubscribeMode(SUBSCRIBE_MODE_MANAGE);
    EXPECT_TRUE(manager_->ShouldMonitorDevice(otherKey));

    manager_->SetSubscribeMode(SUBSCRIBE_MODE_AUTH);
    subscription.reset();
    EXPECT_FALSE(manager_->ShouldMonitorDevice(otherKey));
}

TEST_F(DeviceStatusManagerTest, RefreshDeviceListAddsAndRemovesDevices)
{
    manager_->currentMode_ = SUBSCRIBE_MODE_MANAGE;

    auto statusA = MakePhysicalStatus("device-A", ChannelId::SOFTBUS, "DeviceA");
    auto statusB = MakePhysicalStatus("device-B", ChannelId::SOFTBUS, "DeviceB");

    EXPECT_CALL(*mockChannel_, GetAllPhysicalDevices())
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { statusA, statusB }))
        .WillOnce(Return(std::vector<PhysicalDeviceStatus> { statusB }));

    manager_->RefreshDeviceList(false);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(2u, manager_->deviceStatusMap_.size());
    EXPECT_TRUE(manager_->deviceStatusMap_.count(statusA.physicalDeviceKey));
    EXPECT_TRUE(manager_->deviceStatusMap_.count(statusB.physicalDeviceKey));
    EXPECT_EQ("DeviceA", manager_->deviceStatusMap_.at(statusA.physicalDeviceKey).deviceName);

    manager_->RefreshDeviceList(false);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(1u, manager_->deviceStatusMap_.size());
    EXPECT_FALSE(manager_->deviceStatusMap_.count(statusA.physicalDeviceKey));
    EXPECT_TRUE(manager_->deviceStatusMap_.count(statusB.physicalDeviceKey));
}

TEST_F(DeviceStatusManagerTest, SpecificDeviceSubscriptionTriggersRefreshOnSubscribeAndUnsubscribe)
{
    PhysicalDeviceKey targetKey;
    targetKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    targetKey.deviceId = "device-refresh";

    EXPECT_CALL(*mockChannel_, GetAllPhysicalDevices())
        .Times(2)
        .WillRepeatedly(Return(std::vector<PhysicalDeviceStatus> {}));

    auto subscription =
        manager_->SubscribeDeviceStatus(MakeDeviceKey(targetKey), [](const std::vector<DeviceStatus> &) {});
    subscription.reset();
}

TEST_F(DeviceStatusManagerTest, TriggerDeviceSyncStartsRequestAndHandlesCallback)
{
    LocalDeviceStatus localStatus;
    localStatus.protocolPriorityList = { ProtocolId::VERSION_1 };
    localStatus.protocols = { ProtocolId::VERSION_1 };
    localStatus.capabilities = { Capability::TOKEN_AUTH };
    localStatusManager_->localDeviceStatus_ = localStatus;

    auto physicalStatus = MakePhysicalStatus("device-sync", ChannelId::SOFTBUS, "DeviceSync");
    DeviceStatusEntry entry(physicalStatus);
    entry.isSynced = false;
    entry.isSyncInProgress = false;
    manager_->deviceStatusMap_.emplace(physicalStatus.physicalDeviceKey, entry);

    auto deviceKey = MakeDeviceKey(physicalStatus.physicalDeviceKey);

    bool notified = false;
    auto subscription = manager_->SubscribeDeviceStatus(
        [&](const std::vector<DeviceStatus> &statusList) { notified = !statusList.empty(); });
    (void)subscription;

    EXPECT_CALL(requestFactory_, CreateHostSyncDeviceStatusRequest(_, _, _, _))
        .WillOnce(Invoke([&](UserId hostUserId, const DeviceKey &key, const std::string &deviceName,
                             SyncDeviceStatusCallback &&callback) {
            (void)callback;
            auto request =
                std::make_shared<HostSyncDeviceStatusRequest>(hostUserId, key, deviceName, SyncDeviceStatusCallback {});
            return request;
        }));

    EXPECT_CALL(requestManager_, Start)
        .WillOnce(DoAll(Invoke([&](const std::shared_ptr<IRequest> &request) {
            EXPECT_NE(nullptr, request);
            const auto &inProgressEntry = manager_->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
            EXPECT_TRUE(inProgressEntry.isSyncInProgress);
        }),
            Return(true)));

    manager_->TriggerDeviceSync(physicalStatus.physicalDeviceKey);
    SyncDeviceStatus syncStatus;
    syncStatus.protocolIdList = { ProtocolId::VERSION_1 };
    syncStatus.capabilityList = { Capability::TOKEN_AUTH };
    syncStatus.deviceUserName = "remote-user";
    syncStatus.secureProtocolId = SecureProtocolId::DEFAULT;
    manager_->HandleSyncResult(deviceKey, SUCCESS, syncStatus);
    TaskRunnerManager::GetInstance().ExecuteAll();

    auto storedEntry = manager_->deviceStatusMap_.at(physicalStatus.physicalDeviceKey);
    EXPECT_TRUE(storedEntry.isSynced);
    EXPECT_FALSE(storedEntry.isSyncInProgress);
    EXPECT_EQ("remote-user", storedEntry.deviceUserName);
    EXPECT_TRUE(notified);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
