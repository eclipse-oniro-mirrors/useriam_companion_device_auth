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

#include "mock_guard.h"
#include "soft_bus_connection.h"
#include "soft_bus_connection_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr uint64_t UINT64_1 = 1;
constexpr int32_t DEFAULT_TEST_SOCKET_ID = 100;
constexpr const char *DEFAULT_TEST_CONNECTION_NAME = "test-connection";
constexpr const char *TEST_DEVICE_ID = "test-device";

class SoftbusConnectionTest : public Test {
protected:
    uint64_t nextGlobalId_ = UINT64_1;
    std::shared_ptr<SoftBusConnectionManager> manager_;
};

HWTEST_F(SoftbusConnectionTest, Constructor_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager_);
    ASSERT_NE(connection, nullptr);

    EXPECT_EQ(connection->GetSocketId(), DEFAULT_TEST_SOCKET_ID);
    EXPECT_EQ(connection->GetConnectionName(), DEFAULT_TEST_CONNECTION_NAME);
    EXPECT_EQ(connection->GetPhysicalDeviceKey().deviceId, TEST_DEVICE_ID);
    EXPECT_FALSE(connection->IsConnected());
    EXPECT_FALSE(connection->IsInbound());
}

HWTEST_F(SoftbusConnectionTest, Constructor_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, manager_);
    ASSERT_NE(connection, nullptr);

    EXPECT_EQ(connection->GetSocketId(), DEFAULT_TEST_SOCKET_ID);
    EXPECT_TRUE(connection->GetConnectionName().empty());
    EXPECT_EQ(connection->GetPhysicalDeviceKey().deviceId, TEST_DEVICE_ID);
    EXPECT_FALSE(connection->IsConnected());
    EXPECT_TRUE(connection->IsInbound());
}

HWTEST_F(SoftbusConnectionTest, SetCloseReason_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager_);
    ASSERT_NE(connection, nullptr);

    connection->SetCloseReason("test-reason");

    EXPECT_EQ(connection->closeReason_, "test-reason");
}

HWTEST_F(SoftbusConnectionTest, SetConnectionName_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, manager_);
    ASSERT_NE(connection, nullptr);

    connection->SetConnectionName("new-connection");
    EXPECT_EQ(connection->GetConnectionName(), "new-connection");
}

HWTEST_F(SoftbusConnectionTest, HandleOutboundConnected_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    bool callbackInvoked = false;
    auto subscription = manager_->SubscribeConnectionStatus(
        [&callbackInvoked](const std::string &name, ConnectionStatus status, const std::string &) {
            if (name == "test-connection" && status == ConnectionStatus::CONNECTED) {
                callbackInvoked = true;
            }
        });

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager_);
    ASSERT_NE(connection, nullptr);

    connection->HandleOutboundConnected();

    EXPECT_TRUE(connection->IsConnected());
    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SoftbusConnectionTest, HandleOutboundConnected_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager_);
    ASSERT_NE(connection, nullptr);

    connection->isConnected_ = true;
    connection->HandleOutboundConnected();
}

HWTEST_F(SoftbusConnectionTest, HandleInboundConnected_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;
    bool incomingCallbackInvoked = false;
    auto incomingSubscription = manager_->SubscribeIncomingConnection(
        [&incomingCallbackInvoked](const std::string &name, const PhysicalDeviceKey &) {
            if (name == "test-connection") {
                incomingCallbackInvoked = true;
            }
        });

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, manager_);
    ASSERT_NE(connection, nullptr);

    connection->HandleInboundConnected("test-connection");

    EXPECT_TRUE(connection->IsConnected());
    EXPECT_EQ(connection->GetConnectionName(), DEFAULT_TEST_CONNECTION_NAME);
    EXPECT_TRUE(incomingCallbackInvoked);
}

HWTEST_F(SoftbusConnectionTest, HandleInboundConnected_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, manager_);
    ASSERT_NE(connection, nullptr);

    connection->isConnected_ = true;
    connection->HandleInboundConnected("test-connection");
}

HWTEST_F(SoftbusConnectionTest, HandleInboundConnected_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, "existing-connection", key, manager_);
    ASSERT_NE(connection, nullptr);

    connection->HandleInboundConnected("new-connection");
    EXPECT_EQ(connection->GetConnectionName(), "existing-connection");
}

HWTEST_F(SoftbusConnectionTest, MarkShutdownByPeer_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager_);
    ASSERT_NE(connection, nullptr);

    connection->MarkShutdownByPeer();

    EXPECT_TRUE(connection->isShutdownByPeer_);
}

HWTEST_F(SoftbusConnectionTest, Destructor_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    bool callbackInvoked = false;
    auto subscription = manager_->SubscribeConnectionStatus(
        [&callbackInvoked](const std::string &name, ConnectionStatus status, const std::string &) {
            if (name == "test-connection" && status == ConnectionStatus::DISCONNECTED) {
                callbackInvoked = true;
            }
        });

    {
        auto connection =
            std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager_);
        ASSERT_NE(connection, nullptr);
    }

    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SoftbusConnectionTest, Destructor_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    {
        auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, manager_);
        ASSERT_NE(connection, nullptr);
        connection->socketId_ = -1;
    }
}

HWTEST_F(SoftbusConnectionTest, Destructor_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    {
        auto connection =
            std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager_);
        ASSERT_NE(connection, nullptr);
        connection->socketId_ = -1;
        connection->MarkShutdownByPeer();
    }
}

HWTEST_F(SoftbusConnectionTest, NotifyConnectionEstablished_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, manager_);
    ASSERT_NE(connection, nullptr);

    connection->NotifyConnectionEstablished();
}

HWTEST_F(SoftbusConnectionTest, NotifyConnectionClosed_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, manager_);
    ASSERT_NE(connection, nullptr);

    connection->NotifyConnectionClosed();
}

HWTEST_F(SoftbusConnectionTest, NotifyIncomingConnection_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, manager_);
    ASSERT_NE(connection, nullptr);
    connection->isInbound_ = false;

    connection->NotifyIncomingConnection();
}

HWTEST_F(SoftbusConnectionTest, NotifyIncomingConnection_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, manager_);
    ASSERT_NE(connection, nullptr);

    connection->NotifyIncomingConnection();
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
