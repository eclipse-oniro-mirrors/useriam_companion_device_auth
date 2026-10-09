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

#include "mock_cross_device_channel.h"
#include "mock_guard.h"

#include "cross_device_comm_manager_impl.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class CrossDeviceCommManagerImplTest : public Test {
public:
    std::shared_ptr<NiceMock<MockCrossDeviceChannel>> SetupMockChannel()
    {
        auto mockChannel = std::make_shared<NiceMock<MockCrossDeviceChannel>>();

        PhysicalDeviceKey localPhysicalKey;
        localPhysicalKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        localPhysicalKey.deviceId = "local-device";

        ON_CALL(*mockChannel, GetChannelId()).WillByDefault(Return(ChannelId::SOFTBUS));
        ON_CALL(*mockChannel, GetLocalPhysicalDeviceKey()).WillByDefault(Return(localPhysicalKey));
        ON_CALL(*mockChannel, SubscribeAuthMaintainActive(_)).WillByDefault(Invoke([](OnAuthMaintainActiveChange &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel, GetAuthMaintainActive()).WillByDefault(Return(false));
        ON_CALL(*mockChannel, GetCompanionSecureProtocolId()).WillByDefault(Return(SecureProtocolId::DEFAULT));
        ON_CALL(*mockChannel, SubscribeConnectionStatus(_)).WillByDefault(Invoke([](OnConnectionStatusChange &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel, SubscribeIncomingConnection(_)).WillByDefault(Invoke([](OnIncomingConnection &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel, SubscribeRawMessage(_)).WillByDefault(Invoke([](OnRawMessage &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel, SubscribePhysicalDeviceStatus(_))
            .WillByDefault(Invoke([](OnPhysicalDeviceStatusChange &&) { return MakeSubscription(); }));
        ON_CALL(*mockChannel, GetAllPhysicalDevices()).WillByDefault(Return(std::vector<PhysicalDeviceStatus> {}));
        ON_CALL(*mockChannel, Start()).WillByDefault(Return(true));

        return mockChannel;
    }
};

HWTEST_F(CrossDeviceCommManagerImplTest, Create_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    EXPECT_NE(manager, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Create_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = {};
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Create_003, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    EXPECT_CALL(*mockChannel, SubscribeAuthMaintainActive(_)).WillOnce(Return(nullptr));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Create_004, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    EXPECT_CALL(guard.GetUserKeyManager(), SubscribeUnlockedActiveUserKey(_)).WillOnce(Return(nullptr));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Start_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    EXPECT_CALL(*mockChannel, Start()).WillOnce(Return(true));

    bool result = manager->Start();
    EXPECT_TRUE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Start_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    EXPECT_CALL(*mockChannel, Start()).WillOnce(Return(true));

    bool result1 = manager->Start();
    EXPECT_TRUE(result1);

    bool result2 = manager->Start();
    EXPECT_TRUE(result2);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Start_003, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    EXPECT_CALL(*mockChannel, Start()).WillOnce(Return(false));

    bool result = manager->Start();
    EXPECT_FALSE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeIsAuthMaintainActive_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeIsAuthMaintainActive([callbackInvoked](bool) { *callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetDeviceStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    auto status = manager->GetDeviceStatus(deviceKey);
    EXPECT_FALSE(status.has_value());
}

HWTEST_F(CrossDeviceCommManagerImplTest, IsPhysicalOnline_001, TestSize.Level0)
{
    MockGuard guard;

    PhysicalDeviceStatus onlineStatus;
    onlineStatus.physicalDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    onlineStatus.physicalDeviceKey.deviceId = "online-device";
    onlineStatus.channelId = ChannelId::SOFTBUS;
    onlineStatus.deviceName = "online";

    auto mockChannel = SetupMockChannel();
    ON_CALL(*mockChannel, GetAllPhysicalDevices())
        .WillByDefault(Return(std::vector<PhysicalDeviceStatus> { onlineStatus }));
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "online-device";
    deviceKey.deviceUserId = 100;

    DeviceKey unknownKey = deviceKey;
    unknownKey.deviceId = "unknown-device";

    // Without a specific-device subscription the channel device is filtered out, so it is not online.
    EXPECT_FALSE(manager->IsPhysicalOnline(deviceKey));

    auto subscription =
        manager->SubscribeDeviceStatus(deviceKey, SyncDemand::NONE, [](const std::vector<DeviceStatus> &) {});
    EXPECT_NE(subscription, nullptr);
    EXPECT_TRUE(manager->IsPhysicalOnline(deviceKey));
    EXPECT_FALSE(manager->IsPhysicalOnline(unknownKey));

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetAllDeviceStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    auto allStatus = manager->GetAllDeviceStatus();
    EXPECT_TRUE(allStatus.empty());
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeAllDeviceStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeAllDeviceStatus(
        [callbackInvoked](const std::vector<DeviceStatus> &) { *callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, SetSubscribeMode_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    manager->SetSubscribeMode(SUBSCRIBE_MODE_ALL_DEVICES);
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetCurrentConnectionMode_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    EXPECT_EQ(manager->GetSubscribeMode(), SUBSCRIBE_MODE_SUBSCRIBED_ONLY);
    EXPECT_EQ(manager->GetCurrentConnectionMode(), ConnectionMode::BACKGROUND);

    manager->SetSubscribeMode(SUBSCRIBE_MODE_ALL_DEVICES);
    EXPECT_EQ(manager->GetSubscribeMode(), SUBSCRIBE_MODE_ALL_DEVICES);
    EXPECT_EQ(manager->GetCurrentConnectionMode(), ConnectionMode::FOREGROUND);

    manager->SetSubscribeMode(SUBSCRIBE_MODE_SUBSCRIBED_ONLY);
    EXPECT_EQ(manager->GetSubscribeMode(), SUBSCRIBE_MODE_SUBSCRIBED_ONLY);
    EXPECT_EQ(manager->GetCurrentConnectionMode(), ConnectionMode::BACKGROUND);

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetTemplateStatusSubscribeTimeMs_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    auto subscribeTime = manager->GetTemplateStatusSubscribeTimeMs();
    EXPECT_FALSE(subscribeTime.has_value());
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeDeviceStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeDeviceStatus(deviceKey, SyncDemand::FOLLOW_SUBSCRIBE_MODE,
        [callbackInvoked](const std::vector<DeviceStatus> &) { *callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

// An ensure for an unadopted device settles with COMMUNICATION_ERROR: the device is either not
// managed or the channel cannot enumerate it right now (section 3.1 settlement table).
HWTEST_F(CrossDeviceCommManagerImplTest, EnsureDeviceSynced_UnadoptedDeviceSettlesCommunicationError, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey physicalKey;
    physicalKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    physicalKey.deviceId = "unmonitored-device";

    bool onResultCalled = false;
    ResultCode syncResult = ResultCode::SUCCESS;
    manager->EnsureDeviceSynced(physicalKey, [&onResultCalled, &syncResult](ResultCode resultCode) {
        onResultCalled = true;
        syncResult = resultCode;
    });

    // The trigger is posted to the resident runner: nothing executes synchronously.
    EXPECT_FALSE(onResultCalled);

    // Two resident hops (the forwarded trigger, then the rejection settle): drain transitively.
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    // The forwarded rejection of the unmonitored device is delivered only after the resident task runs.
    EXPECT_TRUE(onResultCalled);
    EXPECT_EQ(syncResult, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(CrossDeviceCommManagerImplTest, OpenConnection_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "remote-device";
    deviceKey.deviceUserId = 100;

    std::string connectionName;
    bool result = manager->OpenConnection(deviceKey, ConnectionMode::FOREGROUND, connectionName);
    EXPECT_FALSE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, CloseConnection_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    manager->CloseConnection("test-connection", "test");
}

HWTEST_F(CrossDeviceCommManagerImplTest, IsConnectionOpen_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    bool result = manager->IsConnectionOpen("test-connection");
    EXPECT_FALSE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetConnectionStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    auto status = manager->GetConnectionStatus("test-connection");
    EXPECT_EQ(status, ConnectionStatus::DISCONNECTED);
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetLocalDeviceKeyByConnectionName_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    auto deviceKey = manager->GetLocalDeviceKeyByConnectionName("test-connection");
    EXPECT_FALSE(deviceKey.has_value());
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetLocalDeviceKeyByConnectionName_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    auto deviceKey = manager->GetLocalDeviceKeyByConnectionName("");
    EXPECT_FALSE(deviceKey.has_value());
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeConnectionStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeConnectionStatus("test-connection",
        [callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { *callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeIncomingConnection_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeIncomingConnection(MessageType::TOKEN_AUTH,
        [callbackInvoked](const Attributes &, OnMessageReply &) { *callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, SendMessage_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    Attributes request;
    bool result = manager->SendMessage("test-connection", MessageType::KEEP_ALIVE, request, nullptr);
    EXPECT_FALSE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeMessage_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeMessage("test-connection", MessageType::TOKEN_AUTH,
        [callbackInvoked](const Attributes &, OnMessageReply &) { *callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, CheckOperationIntent_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    bool result = manager->CheckOperationIntent(deviceKey, 123, nullptr);
    EXPECT_FALSE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, CheckOperationIntent_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    auto callbackInvoked = std::make_shared<bool>(false);
    bool result = manager->CheckOperationIntent(deviceKey, 123, [callbackInvoked](bool) { *callbackInvoked = true; });
    EXPECT_FALSE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, HostGetSecureProtocolId_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    DeviceKey companionDeviceKey;
    companionDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    companionDeviceKey.deviceId = "companion-device";
    companionDeviceKey.deviceUserId = 100;

    auto protocolIdOpt = manager->HostGetSecureProtocolId(companionDeviceKey);
    EXPECT_FALSE(protocolIdOpt.has_value());
}

HWTEST_F(CrossDeviceCommManagerImplTest, CompanionGetSecureProtocolId_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto manager = CrossDeviceCommManagerImpl::Create(
        { .hostSupportedBusinessIds = { BusinessId::DEFAULT },
            .hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
        channels, false);
    ASSERT_NE(manager, nullptr);

    auto protocolId = manager->CompanionGetSecureProtocolId();
    EXPECT_NE(protocolId, SecureProtocolId::INVALID);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
