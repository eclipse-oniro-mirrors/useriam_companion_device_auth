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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "channel_manager.h"
#include "connection_manager.h"
#include "local_device_status_manager.h"
#include "mock_active_user_id_manager.h"
#include "mock_cross_device_channel.h"
#include "mock_misc_manager.h"
#include "relative_timer.h"
#include "singleton_manager.h"
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

class ConnectionManagerTest : public Test {
public:
    void SetUp() override
    {
        const int32_t defaultUserId = 100;

        SingletonManager::GetInstance().Reset();

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto activeUserMgr =
            std::shared_ptr<IActiveUserIdManager>(&mockActiveUserIdManager_, [](IActiveUserIdManager *) {});
        SingletonManager::GetInstance().SetActiveUserIdManager(activeUserMgr);

        ON_CALL(mockMiscManager_, GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });
        ON_CALL(mockActiveUserIdManager_, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
            return MakeSubscription();
        }));
        ON_CALL(mockActiveUserIdManager_, GetActiveUserId()).WillByDefault(Return(defaultUserId));

        mockChannel_ = std::make_shared<NiceMock<MockCrossDeviceChannel>>();

        PhysicalDeviceKey localPhysicalKey;
        localPhysicalKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        localPhysicalKey.deviceId = "local-device";

        ON_CALL(*mockChannel_, GetChannelId()).WillByDefault(Return(ChannelId::SOFTBUS));
        ON_CALL(*mockChannel_, GetLocalPhysicalDeviceKey()).WillByDefault(Return(localPhysicalKey));
        ON_CALL(*mockChannel_, SubscribeAuthMaintainActive(_)).WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(*mockChannel_, GetAuthMaintainActive()).WillByDefault(Return(false));
        ON_CALL(*mockChannel_, GetcompanionSecureProtocolId()).WillByDefault(Return(SecureProtocolId::DEFAULT));
        ON_CALL(*mockChannel_, OpenConnection(_, _)).WillByDefault(Return(true));
        ON_CALL(*mockChannel_, SubscribeConnectionStatus(_))
            .WillByDefault(Invoke([this](OnConnectionStatusChange &&callback) {
                connectionStatusCallback_ = std::move(callback);
                return MakeSubscription();
            }));
        ON_CALL(*mockChannel_, SubscribeIncomingConnection(_))
            .WillByDefault(Invoke([this](OnIncomingConnection &&callback) {
                incomingConnectionCallback_ = std::move(callback);
                return MakeSubscription();
            }));

        std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
        channelMgr_ = std::make_shared<ChannelManager>(channels);
        localDeviceStatusMgr_ = LocalDeviceStatusManager::Create(channelMgr_);
        ASSERT_NE(localDeviceStatusMgr_, nullptr);
    }

    void TearDown() override
    {
        connectionMgr_.reset();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    int32_t nextGlobalId_ = 1;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockActiveUserIdManager> mockActiveUserIdManager_;
    std::shared_ptr<NiceMock<MockCrossDeviceChannel>> mockChannel_;
    std::shared_ptr<ChannelManager> channelMgr_;
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr_;
    std::shared_ptr<ConnectionManager> connectionMgr_;
    OnConnectionStatusChange connectionStatusCallback_;
    OnIncomingConnection incomingConnectionCallback_;
};

HWTEST_F(ConnectionManagerTest, Create_001, TestSize.Level0)
{
    auto manager = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    EXPECT_NE(manager, nullptr);
}

HWTEST_F(ConnectionManagerTest, Create_002, TestSize.Level0)
{
    auto manager = ConnectionManager::Create(nullptr, localDeviceStatusMgr_);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(ConnectionManagerTest, Create_003, TestSize.Level0)
{
    EXPECT_CALL(*mockChannel_, SubscribeConnectionStatus(_)).WillOnce(Return(nullptr));
    EXPECT_CALL(*mockChannel_, SubscribeIncomingConnection(_)).WillOnce(Return(nullptr));

    auto manager = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    EXPECT_NE(manager, nullptr);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    EXPECT_CALL(*mockChannel_, OpenConnection(_, _)).WillOnce(Return(true));

    std::string connectionName;
    bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);

    EXPECT_TRUE(result);
    EXPECT_FALSE(connectionName.empty());

    auto connection = connectionMgr_->GetConnection(connectionName);
    ASSERT_TRUE(connection.has_value());
    EXPECT_EQ(connection->connectionStatus, ConnectionStatus::ESTABLISHING);
    EXPECT_FALSE(connection->isInbound);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_002, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    EXPECT_CALL(*mockChannel_, OpenConnection(_, _)).WillOnce(Return(false));

    std::string connectionName;
    bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);

    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_003, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::HEAD_PHONE_MANAGER, connectionName);

    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_004, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    PhysicalDeviceKey localPhysicalKey;
    localPhysicalKey.idType = DeviceIdType::UNKNOWN;
    localPhysicalKey.deviceId = "local-device";

    EXPECT_CALL(*mockChannel_, GetLocalPhysicalDeviceKey()).WillOnce(Return(localPhysicalKey));

    std::string connectionName;
    bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);

    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_005, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    PhysicalDeviceKey localPhysicalKey;
    localPhysicalKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    localPhysicalKey.deviceId = "";

    EXPECT_CALL(*mockChannel_, GetLocalPhysicalDeviceKey()).WillOnce(Return(localPhysicalKey));

    std::string connectionName;
    bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);

    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_006, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    for (size_t i = 0; i < 100; ++i) {
        PhysicalDeviceKey remoteKey;
        remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        remoteKey.deviceId = "device-" + std::to_string(i);

        std::string connectionName;
        bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
        EXPECT_TRUE(result);
    }

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "device-overflow";

    std::string connectionName;
    bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, OpenConnection_007, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "same-device";

    for (size_t i = 0; i < 10; ++i) {
        std::string connectionName;
        bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
        EXPECT_TRUE(result);
    }

    std::string connectionName;
    bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    EXPECT_FALSE(result);
}

HWTEST_F(ConnectionManagerTest, CloseConnection_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    bool notified = false;
    auto subscription = connectionMgr_->SubscribeConnectionStatus(connectionName,
        [&notified](const std::string &, ConnectionStatus status, const std::string &) {
            if (status == ConnectionStatus::DISCONNECTED) {
                notified = true;
            }
        });

    connectionMgr_->CloseConnection(connectionName, "test_close");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(notified);
    auto connection = connectionMgr_->GetConnection(connectionName);
    EXPECT_FALSE(connection.has_value());
}

HWTEST_F(ConnectionManagerTest, CloseConnection_002, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    connectionMgr_->CloseConnection("non-existent-connection", "test");
}

HWTEST_F(ConnectionManagerTest, HandleIncomingConnection_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result = connectionMgr_->HandleIncomingConnection("incoming-conn", remoteKey);
    EXPECT_TRUE(result);

    auto connection = connectionMgr_->GetConnection("incoming-conn");
    ASSERT_TRUE(connection.has_value());
    EXPECT_EQ(connection->connectionStatus, ConnectionStatus::CONNECTED);
    EXPECT_TRUE(connection->isInbound);
}

HWTEST_F(ConnectionManagerTest, HandleIncomingConnection_002, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result1 = connectionMgr_->HandleIncomingConnection("incoming-conn", remoteKey);
    EXPECT_TRUE(result1);

    bool result2 = connectionMgr_->HandleIncomingConnection("incoming-conn", remoteKey);
    EXPECT_TRUE(result2);
}

HWTEST_F(ConnectionManagerTest, GetConnection_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    auto connection = connectionMgr_->GetConnection("non-existent");
    EXPECT_FALSE(connection.has_value());
}

HWTEST_F(ConnectionManagerTest, GetConnectionStatus_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    auto status = connectionMgr_->GetConnectionStatus("non-existent");
    EXPECT_EQ(status, ConnectionStatus::DISCONNECTED);
}

HWTEST_F(ConnectionManagerTest, SubscribeConnectionStatus_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    bool callbackInvoked = false;
    auto subscription = connectionMgr_->SubscribeConnectionStatus("test-conn",
        [&callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    connectionMgr_->HandleIncomingConnection("test-conn", remoteKey);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(ConnectionManagerTest, SubscribeConnectionStatus_002, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    auto subscription = connectionMgr_->SubscribeConnectionStatus("", nullptr);
    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(ConnectionManagerTest, SubscribeConnectionStatus_003, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    bool callbackInvoked = false;
    {
        auto subscription = connectionMgr_->SubscribeConnectionStatus("test-conn",
            [&callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { callbackInvoked = true; });
        EXPECT_NE(subscription, nullptr);
    }

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    connectionMgr_->HandleIncomingConnection("test-conn", remoteKey);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackInvoked);
}

HWTEST_F(ConnectionManagerTest, HandleChannelConnectionStatusChange_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    bool notified = false;
    auto subscription = connectionMgr_->SubscribeConnectionStatus(connectionName,
        [&notified](const std::string &, ConnectionStatus status, const std::string &) {
            if (status == ConnectionStatus::CONNECTED) {
                notified = true;
            }
        });

    ASSERT_TRUE(connectionStatusCallback_ != nullptr);
    connectionStatusCallback_(connectionName, ConnectionStatus::CONNECTED, "established");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(notified);
    auto connection = connectionMgr_->GetConnection(connectionName);
    ASSERT_TRUE(connection.has_value());
    EXPECT_EQ(connection->connectionStatus, ConnectionStatus::CONNECTED);
}

HWTEST_F(ConnectionManagerTest, HandleChannelConnectionStatusChange_002, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    bool notified = false;
    auto subscription = connectionMgr_->SubscribeConnectionStatus(connectionName,
        [&notified](const std::string &, ConnectionStatus status, const std::string &) {
            if (status == ConnectionStatus::DISCONNECTED) {
                notified = true;
            }
        });

    ASSERT_TRUE(connectionStatusCallback_ != nullptr);
    connectionStatusCallback_(connectionName, ConnectionStatus::DISCONNECTED, "peer_closed");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(notified);
    auto connection = connectionMgr_->GetConnection(connectionName);
    EXPECT_FALSE(connection.has_value());
}

HWTEST_F(ConnectionManagerTest, HandleIncomingConnectionFromChannel_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool notified = false;
    auto subscription = connectionMgr_->SubscribeConnectionStatus("incoming-from-channel",
        [&notified](const std::string &, ConnectionStatus status, const std::string &) {
            if (status == ConnectionStatus::CONNECTED) {
                notified = true;
            }
        });

    ASSERT_TRUE(incomingConnectionCallback_ != nullptr);
    incomingConnectionCallback_("incoming-from-channel", remoteKey);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(notified);
    auto connection = connectionMgr_->GetConnection("incoming-from-channel");
    ASSERT_TRUE(connection.has_value());
    EXPECT_TRUE(connection->isInbound);
}

HWTEST_F(ConnectionManagerTest, HandleKeepAliveReply_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result = connectionMgr_->HandleIncomingConnection("test-conn", remoteKey);
    ASSERT_TRUE(result);

    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));

    connectionMgr_->HandleKeepAliveReply("test-conn", reply);
}

HWTEST_F(ConnectionManagerTest, HandleKeepAliveReply_002, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));

    connectionMgr_->HandleKeepAliveReply("non-existent", reply);
}

HWTEST_F(ConnectionManagerTest, HandleKeepAliveReply_003, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result = connectionMgr_->HandleIncomingConnection("test-conn", remoteKey);
    ASSERT_TRUE(result);

    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::GENERAL_ERROR));

    connectionMgr_->HandleKeepAliveReply("test-conn", reply);
}

HWTEST_F(ConnectionManagerTest, HandleKeepAliveReply_004, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    bool result = connectionMgr_->HandleIncomingConnection("test-conn", remoteKey);
    ASSERT_TRUE(result);

    Attributes reply;

    connectionMgr_->HandleKeepAliveReply("test-conn", reply);
}

HWTEST_F(ConnectionManagerTest, HandleChannelConnectionEstablished_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    connectionMgr_->HandleChannelConnectionEstablished("test-conn");
}

HWTEST_F(ConnectionManagerTest, HandleChannelConnectionClosed_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    connectionMgr_->HandleChannelConnectionClosed("test-conn", "");
}

HWTEST_F(ConnectionManagerTest, HandleIdleMonitorTimer_001, TestSize.Level0)
{
    connectionMgr_ = ConnectionManager::Create(channelMgr_, localDeviceStatusMgr_);
    ASSERT_NE(connectionMgr_, nullptr);

    PhysicalDeviceKey remoteKey;
    remoteKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    remoteKey.deviceId = "remote-device";

    std::string connectionName;
    bool result = connectionMgr_->OpenConnection(remoteKey, ChannelId::SOFTBUS, connectionName);
    ASSERT_TRUE(result);

    connectionMgr_->HandleIdleMonitorTimer();
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
