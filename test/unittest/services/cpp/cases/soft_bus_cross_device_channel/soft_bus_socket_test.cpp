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

#include "relative_timer.h"
#include "singleton_manager.h"
#include "soft_bus_connection_manager.h"
#include "soft_bus_socket.h"
#include "task_runner_manager.h"

#include "mock_misc_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class SoftBusSocketTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        ON_CALL(mockMiscManager_, GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

        manager_ = SoftBusConnectionManager::Create();
        ASSERT_NE(manager_, nullptr);
    }

    void TearDown() override
    {
        manager_.reset();
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    int32_t nextGlobalId_ = 1;
    NiceMock<MockMiscManager> mockMiscManager_;
    std::shared_ptr<SoftBusConnectionManager> manager_;
};

HWTEST_F(SoftBusSocketTest, Constructor_001, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, "test-connection", key, manager_);
    ASSERT_NE(socket, nullptr);

    EXPECT_EQ(socket->GetSocketId(), 100);
    EXPECT_EQ(socket->GetConnectionName(), "test-connection");
    EXPECT_EQ(socket->GetPhysicalDeviceKey().deviceId, "test-device");
    EXPECT_FALSE(socket->IsConnected());
    EXPECT_FALSE(socket->IsInbound());
}

HWTEST_F(SoftBusSocketTest, Constructor_002, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, key, manager_);
    ASSERT_NE(socket, nullptr);

    EXPECT_EQ(socket->GetSocketId(), 100);
    EXPECT_TRUE(socket->GetConnectionName().empty());
    EXPECT_EQ(socket->GetPhysicalDeviceKey().deviceId, "test-device");
    EXPECT_FALSE(socket->IsConnected());
    EXPECT_TRUE(socket->IsInbound());
}

HWTEST_F(SoftBusSocketTest, SetCloseReason_001, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, "test-connection", key, manager_);
    ASSERT_NE(socket, nullptr);

    socket->SetCloseReason("test-reason");

    EXPECT_EQ(socket->closeReason_, "test-reason");
}

HWTEST_F(SoftBusSocketTest, SetConnectionName_001, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, key, manager_);
    ASSERT_NE(socket, nullptr);

    socket->SetConnectionName("new-connection");
    EXPECT_EQ(socket->GetConnectionName(), "new-connection");
}

HWTEST_F(SoftBusSocketTest, HandleOutboundConnected_001, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    bool callbackInvoked = false;
    auto subscription = manager_->SubscribeConnectionStatus(
        [&callbackInvoked](const std::string &name, ConnectionStatus status, const std::string &) {
            if (name == "test-connection" && status == ConnectionStatus::CONNECTED) {
                callbackInvoked = true;
            }
        });

    auto socket = std::make_shared<SoftBusSocket>(100, "test-connection", key, manager_);
    ASSERT_NE(socket, nullptr);

    socket->HandleOutboundConnected();
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(socket->IsConnected());
    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SoftBusSocketTest, HandleOutboundConnected_002, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, "test-connection", key, manager_);
    ASSERT_NE(socket, nullptr);

    socket->isConnected_ = true;
    socket->HandleOutboundConnected();
}

HWTEST_F(SoftBusSocketTest, HandleInboundConnected_001, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";
    bool incomingCallbackInvoked = false;
    auto incomingSubscription = manager_->SubscribeIncomingConnection(
        [&incomingCallbackInvoked](const std::string &name, const PhysicalDeviceKey &) {
            if (name == "test-connection") {
                incomingCallbackInvoked = true;
            }
        });

    auto socket = std::make_shared<SoftBusSocket>(100, key, manager_);
    ASSERT_NE(socket, nullptr);

    socket->HandleInboundConnected("test-connection");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(socket->IsConnected());
    EXPECT_EQ(socket->GetConnectionName(), "test-connection");
    EXPECT_TRUE(incomingCallbackInvoked);
}

HWTEST_F(SoftBusSocketTest, HandleInboundConnected_002, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, key, manager_);
    ASSERT_NE(socket, nullptr);

    socket->isConnected_ = true;
    socket->HandleInboundConnected("test-connection");
}

HWTEST_F(SoftBusSocketTest, HandleInboundConnected_003, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, "existing-connection", key, manager_);
    ASSERT_NE(socket, nullptr);

    socket->HandleInboundConnected("new-connection");
    EXPECT_EQ(socket->GetConnectionName(), "existing-connection");
}

HWTEST_F(SoftBusSocketTest, MarkShutdownByPeer_001, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, "test-connection", key, manager_);
    ASSERT_NE(socket, nullptr);

    socket->MarkShutdownByPeer();

    EXPECT_TRUE(socket->isShutdownByPeer_);
}

HWTEST_F(SoftBusSocketTest, Destructor_001, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    bool callbackInvoked = false;
    auto subscription = manager_->SubscribeConnectionStatus(
        [&callbackInvoked](const std::string &name, ConnectionStatus status, const std::string &) {
            if (name == "test-connection" && status == ConnectionStatus::DISCONNECTED) {
                callbackInvoked = true;
            }
        });

    {
        auto socket = std::make_shared<SoftBusSocket>(100, "test-connection", key, manager_);
        ASSERT_NE(socket, nullptr);
    }

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SoftBusSocketTest, Destructor_002, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    {
        auto socket = std::make_shared<SoftBusSocket>(100, key, manager_);
        ASSERT_NE(socket, nullptr);
        socket->socketId_ = -1;
    }
}

HWTEST_F(SoftBusSocketTest, Destructor_003, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    {
        auto socket = std::make_shared<SoftBusSocket>(100, "test-connection", key, manager_);
        ASSERT_NE(socket, nullptr);
        socket->socketId_ = -1;
        socket->MarkShutdownByPeer();
    }
}

HWTEST_F(SoftBusSocketTest, NotifyConnectionEstablished_001, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, key, manager_);
    ASSERT_NE(socket, nullptr);

    socket->NotifyConnectionEstablished();
}

HWTEST_F(SoftBusSocketTest, NotifyConnectionClosed_001, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, key, manager_);
    ASSERT_NE(socket, nullptr);

    socket->NotifyConnectionClosed();
}

HWTEST_F(SoftBusSocketTest, NotifyIncomingConnection_001, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, key, manager_);
    ASSERT_NE(socket, nullptr);
    socket->isInbound_ = false;

    socket->NotifyIncomingConnection();
}

HWTEST_F(SoftBusSocketTest, NotifyIncomingConnection_002, TestSize.Level0)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto socket = std::make_shared<SoftBusSocket>(100, key, manager_);
    ASSERT_NE(socket, nullptr);

    socket->NotifyIncomingConnection();
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
