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

#include "channel_manager.h"
#include "connection_manager.h"
#include "local_device_status_manager.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_cross_device_channel.h"
#include "mock_guard.h"

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

class ConnectionManagerTest : public Test {
public:
    std::shared_ptr<NiceMock<MockCrossDeviceChannel>> SetupMockChannel()
    {
        auto mockChannel = std::make_shared<NiceMock<MockCrossDeviceChannel>>();

        PhysicalDeviceKey localPhysicalKey;
        localPhysicalKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        localPhysicalKey.deviceId = "local-device";

        ON_CALL(*mockChannel, GetChannelId()).WillByDefault(Return(ChannelId::SOFTBUS));
        ON_CALL(*mockChannel, GetLocalPhysicalDeviceKey()).WillByDefault(Return(localPhysicalKey));
        EXPECT_CALL(*mockChannel, SubscribeAuthMaintainActive(_))
            .Times(AtMost(1))
            .WillOnce(Return(ByMove(MakeSubscription())));
        ON_CALL(*mockChannel, GetAuthMaintainActive()).WillByDefault(Return(false));
        ON_CALL(*mockChannel, GetCompanionSecureProtocolId()).WillByDefault(Return(SecureProtocolId::DEFAULT));
        ON_CALL(*mockChannel, OpenConnection(_, _)).WillByDefault(Return(true));
        ON_CALL(*mockChannel, SubscribePhysicalDeviceStatus(_))
            .WillByDefault(Invoke([](OnPhysicalDeviceStatusChange &&) { return MakeSubscription(); }));

        return mockChannel;
    }
};

HWTEST_F(ConnectionManagerTest, Create_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    auto manager = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    EXPECT_NE(manager, nullptr);
}

HWTEST_F(ConnectionManagerTest, Create_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    auto manager = ConnectionManager::Create(nullptr, localDeviceStatusMgr);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(ConnectionManagerTest, Create_003, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    EXPECT_CALL(*mockChannel, SubscribeConnectionStatus(_)).WillOnce(Return(nullptr));

    auto manager = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(ConnectionManagerTest, Create_004, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    EXPECT_CALL(*mockChannel, SubscribeIncomingConnection(_)).WillOnce(Return(nullptr));

    auto manager = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(ConnectionManagerTest, Create_005, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    EXPECT_CALL(*mockChannel, SubscribePhysicalDeviceStatus(_)).WillOnce(Return(nullptr));

    auto manager = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    EXPECT_CALL(*mockChannel, OpenConnection(_, _)).WillOnce(Return(true));

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);

    EXPECT_TRUE(result);
    EXPECT_FALSE(connectionName.empty());

    auto connection = connectionMgr->GetConnection(connectionName);
    ASSERT_TRUE(connection.has_value());
    EXPECT_EQ(connection->connectionStatus, ConnectionStatus::ESTABLISHING);
    EXPECT_FALSE(connection->isInbound);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    EXPECT_CALL(*mockChannel, OpenConnection(_, _)).WillOnce(Return(false));

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);

    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_003, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    EXPECT_CALL(*mockChannel, GetLocalPhysicalDeviceKey()).WillOnce(Return(std::nullopt));

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);

    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_004, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    PhysicalDeviceKey localPhysicalKey;
    localPhysicalKey.idType = DeviceIdType::UNKNOWN;
    localPhysicalKey.deviceId = "local-device";

    EXPECT_CALL(*mockChannel, GetLocalPhysicalDeviceKey()).WillOnce(Return(localPhysicalKey));

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);

    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_005, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    PhysicalDeviceKey localPhysicalKey;
    localPhysicalKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    localPhysicalKey.deviceId = "";

    EXPECT_CALL(*mockChannel, GetLocalPhysicalDeviceKey()).WillOnce(Return(localPhysicalKey));

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);

    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_006, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    for (size_t i = 0; i < 100; ++i) {
        PhysicalDeviceKey remoteKey;
        remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        remoteKey.deviceId = "device-" + std::to_string(i);

        std::string connectionName;
        bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
        EXPECT_TRUE(result);
    }

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "device-overflow";

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_007, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    // Set up GetNextGlobalId to return incrementing values
    uint32_t globalIdCounter = 0;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault(Invoke([&globalIdCounter]() -> uint32_t {
        return ++globalIdCounter;
    }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "same-device";

    for (size_t i = 0; i < 10; ++i) {
        std::string connectionName;
        bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
        EXPECT_TRUE(result);
    }

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, CloseConnection_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    bool notified = false;
    auto subscription = connectionMgr->SubscribeConnectionStatus(connectionName,
        [&notified](const std::string &, ConnectionStatus status, const std::string &) {
            if (status == ConnectionStatus::DISCONNECTED) {
                notified = true;
            }
        });

    connectionMgr->CloseConnection(connectionName, "test_close");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(notified);
    auto connection = connectionMgr->GetConnection(connectionName);
    EXPECT_FALSE(connection.has_value());
}

HWTEST_F(ConnectionManagerTest, CloseConnection_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    connectionMgr->CloseConnection("non-existent-connection", "test");
}

HWTEST_F(ConnectionManagerTest, CloseConnection_003, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    EXPECT_CALL(*mockChannel, RequiresDisconnectNotification()).WillOnce(Return(false));

    connectionMgr->CloseConnection(connectionName, "test_close");
}

HWTEST_F(ConnectionManagerTest, CloseConnection_004, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result = connectionMgr->HandleIncomingConnection("test-conn", remoteKey);
    ASSERT_TRUE(result);

    connectionMgr->connectionMap_["test-conn"].isInbound = false;

    EXPECT_CALL(*mockChannel, RequiresDisconnectNotification()).WillOnce(Return(true));

    connectionMgr->CloseConnection("test-conn", "test_close");
}

HWTEST_F(ConnectionManagerTest, HandleIncomingConnection_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result = connectionMgr->HandleIncomingConnection("incoming-conn", remoteKey);
    EXPECT_TRUE(result);

    auto connection = connectionMgr->GetConnection("incoming-conn");
    ASSERT_TRUE(connection.has_value());
    EXPECT_EQ(connection->connectionStatus, ConnectionStatus::CONNECTED);
    EXPECT_TRUE(connection->isInbound);
}

HWTEST_F(ConnectionManagerTest, HandleIncomingConnection_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result1 = connectionMgr->HandleIncomingConnection("incoming-conn", remoteKey);
    EXPECT_TRUE(result1);

    // Second call with same connection name should fail
    bool result2 = connectionMgr->HandleIncomingConnection("incoming-conn", remoteKey);
    EXPECT_FALSE(result2);
}

HWTEST_F(ConnectionManagerTest, HandleIncomingConnection_003, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    for (size_t i = 0; i < 10; ++i) {
        PhysicalDeviceKey remoteKey;
        remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        remoteKey.deviceId = "same-device-incoming";

        bool result = connectionMgr->HandleIncomingConnection("incoming-conn-" + std::to_string(i), remoteKey);
        EXPECT_TRUE(result);
    }

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "same-device-incoming";

    bool result = connectionMgr->HandleIncomingConnection("incoming-conn-overflow", remoteKey);
    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, GetConnection_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    auto connection = connectionMgr->GetConnection("non-existent");
    EXPECT_FALSE(connection.has_value());
}

HWTEST_F(ConnectionManagerTest, GetConnectionStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    auto status = connectionMgr->GetConnectionStatus("non-existent");
    EXPECT_EQ(status, ConnectionStatus::DISCONNECTED);
}

HWTEST_F(ConnectionManagerTest, GetConnectionStatus_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    connectionStatusCallback(connectionName, ConnectionStatus::CONNECTED, "established");

    auto status = connectionMgr->GetConnectionStatus(connectionName);
    EXPECT_EQ(status, ConnectionStatus::CONNECTED);
}

HWTEST_F(ConnectionManagerTest, SubscribeConnectionStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    bool callbackInvoked = false;
    auto subscription = connectionMgr->SubscribeConnectionStatus("test-conn",
        [&callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    connectionMgr->HandleIncomingConnection("test-conn", remoteKey);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(ConnectionManagerTest, SubscribeConnectionStatus_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    auto subscription = connectionMgr->SubscribeConnectionStatus("", nullptr);
    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(ConnectionManagerTest, SubscribeConnectionStatus_003, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    bool callbackInvoked = false;
    {
        auto subscription = connectionMgr->SubscribeConnectionStatus("test-conn",
            [&callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { callbackInvoked = true; });
        EXPECT_NE(subscription, nullptr);
    }

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    connectionMgr->HandleIncomingConnection("test-conn", remoteKey);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackInvoked);
}

HWTEST_F(ConnectionManagerTest, HandleChannelConnectionStatusChange_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    bool notified = false;
    auto subscription = connectionMgr->SubscribeConnectionStatus(connectionName,
        [&notified](const std::string &, ConnectionStatus status, const std::string &) {
            if (status == ConnectionStatus::CONNECTED) {
                notified = true;
            }
        });

    ASSERT_TRUE(connectionStatusCallback != nullptr);
    connectionStatusCallback(connectionName, ConnectionStatus::CONNECTED, "established");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(notified);
    auto connection = connectionMgr->GetConnection(connectionName);
    ASSERT_TRUE(connection.has_value());
    EXPECT_EQ(connection->connectionStatus, ConnectionStatus::CONNECTED);
}

HWTEST_F(ConnectionManagerTest, HandleChannelConnectionStatusChange_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    bool notified = false;
    auto subscription = connectionMgr->SubscribeConnectionStatus(connectionName,
        [&notified](const std::string &, ConnectionStatus status, const std::string &) {
            if (status == ConnectionStatus::DISCONNECTED) {
                notified = true;
            }
        });

    ASSERT_TRUE(connectionStatusCallback != nullptr);
    connectionStatusCallback(connectionName, ConnectionStatus::DISCONNECTED, "peer_closed");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(notified);
    auto connection = connectionMgr->GetConnection(connectionName);
    EXPECT_FALSE(connection.has_value());
}

HWTEST_F(ConnectionManagerTest, HandleChannelConnectionStatusChange_003, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    ASSERT_TRUE(connectionStatusCallback != nullptr);
    connectionStatusCallback(connectionName, ConnectionStatus::ESTABLISHING, "establishing");
}

HWTEST_F(ConnectionManagerTest, HandleIncomingConnectionFromChannel_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool notified = false;
    auto subscription = connectionMgr->SubscribeConnectionStatus("incoming-from-channel",
        [&notified](const std::string &, ConnectionStatus status, const std::string &) {
            if (status == ConnectionStatus::CONNECTED) {
                notified = true;
            }
        });

    ASSERT_TRUE(incomingConnectionCallback != nullptr);
    incomingConnectionCallback("incoming-from-channel", remoteKey);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(notified);
    auto connection = connectionMgr->GetConnection("incoming-from-channel");
    ASSERT_TRUE(connection.has_value());
    EXPECT_TRUE(connection->isInbound);
}

HWTEST_F(ConnectionManagerTest, HandleIncomingConnectionFromChannel_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    for (size_t i = 0; i < 10; ++i) {
        PhysicalDeviceKey remoteKey;
        remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        remoteKey.deviceId = "device-limit";

        incomingConnectionCallback("conn-" + std::to_string(i), remoteKey);
    }

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "device-limit";

    incomingConnectionCallback("conn-overflow", remoteKey);

    auto connection = connectionMgr->GetConnection("conn-overflow");
    EXPECT_FALSE(connection.has_value());
}

HWTEST_F(ConnectionManagerTest, HandleKeepAliveReply_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result = connectionMgr->HandleIncomingConnection("test-conn", remoteKey);
    ASSERT_TRUE(result);

    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));

    connectionMgr->HandleKeepAliveReply("test-conn", reply);
}

HWTEST_F(ConnectionManagerTest, HandleKeepAliveReply_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));

    connectionMgr->HandleKeepAliveReply("non-existent", reply);
}

HWTEST_F(ConnectionManagerTest, HandleKeepAliveReply_003, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result = connectionMgr->HandleIncomingConnection("test-conn", remoteKey);
    ASSERT_TRUE(result);

    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::GENERAL_ERROR));

    connectionMgr->HandleKeepAliveReply("test-conn", reply);
}

HWTEST_F(ConnectionManagerTest, HandleKeepAliveReply_004, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result = connectionMgr->HandleIncomingConnection("test-conn", remoteKey);
    ASSERT_TRUE(result);

    Attributes reply;

    connectionMgr->HandleKeepAliveReply("test-conn", reply);
}

HWTEST_F(ConnectionManagerTest, HandleChannelConnectionEstablished_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    connectionMgr->HandleChannelConnectionEstablished("test-conn");
}

HWTEST_F(ConnectionManagerTest, HandleChannelConnectionClosed_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    connectionMgr->HandleChannelConnectionClosed("test-conn", "");
}

HWTEST_F(ConnectionManagerTest, HandleIdleMonitorTimer_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    connectionMgr->HandleIdleMonitorTimer();
}

HWTEST_F(ConnectionManagerTest, HandlePhysicalDeviceStatusChange_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    bool notified = false;
    auto subscription = connectionMgr->SubscribeConnectionStatus(connectionName,
        [&notified](const std::string &, ConnectionStatus status, const std::string &) {
            if (status == ConnectionStatus::DISCONNECTED) {
                notified = true;
            }
        });

    std::vector<PhysicalDeviceStatus> statusList;
    connectionMgr->HandlePhysicalDeviceStatusChange(ChannelId::SOFTBUS, statusList);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(notified);
    EXPECT_FALSE(connectionMgr->GetConnection(connectionName).has_value());
}

HWTEST_F(ConnectionManagerTest, HandlePhysicalDeviceStatusChange_002, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey1;
    remoteKey1.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey1.deviceId = "remote-device-1";

    PhysicalDeviceKey remoteKey2;
    remoteKey2.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey2.deviceId = "remote-device-2";

    std::string connectionName1;
    bool result1 = connectionMgr->OpenConnection(remoteKey1, ChannelId::SOFTBUS, connectionName1);
    ASSERT_TRUE(result1);

    std::string connectionName2;
    bool result2 = connectionMgr->OpenConnection(remoteKey2, ChannelId::SOFTBUS, connectionName2);
    ASSERT_TRUE(result2);

    PhysicalDeviceStatus status1;
    status1.physicalDeviceKey = remoteKey1;
    status1.channelId = ChannelId::SOFTBUS;

    std::vector<PhysicalDeviceStatus> statusList = { status1 };
    connectionMgr->HandlePhysicalDeviceStatusChange(ChannelId::SOFTBUS, statusList);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(connectionMgr->GetConnection(connectionName1).has_value());
    EXPECT_FALSE(connectionMgr->GetConnection(connectionName2).has_value());
}

HWTEST_F(ConnectionManagerTest, HandlePhysicalDeviceStatusChange_003, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    std::vector<PhysicalDeviceStatus> statusList;
    connectionMgr->HandlePhysicalDeviceStatusChange(ChannelId::SOFTBUS, statusList);

    EXPECT_FALSE(connectionMgr->GetConnection(connectionName).has_value());
}

HWTEST_F(ConnectionManagerTest, NotifyConnectionStatus_WithNullCallback, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    auto subscription = connectionMgr->SubscribeConnectionStatus("test", nullptr);
    EXPECT_EQ(subscription, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result = connectionMgr->HandleIncomingConnection("test-conn", remoteKey);
    ASSERT_TRUE(result);

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(ConnectionManagerTest, SubscribeConnectionStatus_004, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    bool callbackInvoked = false;
    auto subscription = connectionMgr->SubscribeConnectionStatus("",
        [&callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    connectionMgr->HandleIncomingConnection("any-conn", remoteKey);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(ConnectionManagerTest, CheckIdleMonitoring_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    EXPECT_EQ(connectionMgr->idleMonitorTimerSubscription_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    EXPECT_NE(connectionMgr->idleMonitorTimerSubscription_, nullptr);

    connectionMgr->CloseConnection(connectionName, "test");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(connectionMgr->idleMonitorTimerSubscription_, nullptr);
}

HWTEST_F(ConnectionManagerTest, GenerateConnectionName_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    PhysicalDeviceKey remoteKey1;
    remoteKey1.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey1.deviceId = "remote-device-1";

    PhysicalDeviceKey remoteKey2;
    remoteKey2.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey2.deviceId = "remote-device-2";

    std::string connectionName1;
    bool result1 = connectionMgr->OpenConnection(remoteKey1, ChannelId::SOFTBUS, connectionName1);
    ASSERT_TRUE(result1);

    std::string connectionName2;
    bool result2 = connectionMgr->OpenConnection(remoteKey2, ChannelId::SOFTBUS, connectionName2);
    ASSERT_TRUE(result2);

    EXPECT_NE(connectionName1, connectionName2);
}

HWTEST_F(ConnectionManagerTest, UnsubscribeConnectionStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto mockChannel = SetupMockChannel();
    OnConnectionStatusChange connectionStatusCallback;
    OnIncomingConnection incomingConnectionCallback;

    ON_CALL(*mockChannel, SubscribeConnectionStatus(_))
        .WillByDefault(Invoke([&connectionStatusCallback](OnConnectionStatusChange &&callback) {
            connectionStatusCallback = std::move(callback);
            return MakeSubscription();
        }));
    ON_CALL(*mockChannel, SubscribeIncomingConnection(_))
        .WillByDefault(Invoke([&incomingConnectionCallback](OnIncomingConnection &&callback) {
            incomingConnectionCallback = std::move(callback);
            return MakeSubscription();
        }));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel };
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    ASSERT_NE(localDeviceStatusMgr, nullptr);
    std::shared_ptr<ConnectionManager> connectionMgr;
    connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ASSERT_NE(connectionMgr, nullptr);

    bool callbackInvoked = false;
    auto subscription = connectionMgr->SubscribeConnectionStatus("test",
        [&callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { callbackInvoked = true; });

    SubscribeId subscriptionId = connectionMgr->connectionStatusSubscribers_.begin()->first;

    connectionMgr->UnsubscribeConnectionStatus(subscriptionId);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    connectionMgr->HandleIncomingConnection("test", remoteKey);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackInvoked);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
