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
#include "soft_bus_adapter.h"
#include "soft_bus_adapter_manager.h"
#include "soft_bus_connection.h"
#include "soft_bus_connection_manager.h"

#include "mock_soft_bus_adapter.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_2 = 2;
constexpr uint64_t UINT64_1 = 1;
constexpr int32_t DEFAULT_TEST_SOCKET_ID = 100;
constexpr const char *DEFAULT_TEST_CONNECTION_NAME = "test-connection";
constexpr const char *NON_EXISTENT_CONNECTION_NAME = "non-existent-connection";

class SoftBusConnectionManagerTest : public Test {
protected:
    uint64_t nextGlobalId_ = UINT64_1;
    NiceMock<MockSoftBusAdapter> mockSoftBusAdapter_;
};

HWTEST_F(SoftBusConnectionManagerTest, Create_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    EXPECT_NE(manager, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, Start_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool result = manager->Start();
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, Start_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);
    manager->started_ = true;

    bool result = manager->Start();
    EXPECT_TRUE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeRawMessage_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeRawMessage(
        [&callbackInvoked](const std::string &, const std::vector<uint8_t> &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeRawMessage_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto subscription = manager->SubscribeRawMessage(nullptr);
    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeConnectionStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeConnectionStatus(
        [&callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeConnectionStatus_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto subscription = manager->SubscribeConnectionStatus(nullptr);
    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeIncomingConnection_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeIncomingConnection(
        [&callbackInvoked](const std::string &, const PhysicalDeviceKey &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeIncomingConnection_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto subscription = manager->SubscribeIncomingConnection(nullptr);
    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SendMessage_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    std::vector<uint8_t> message = { 1, 2, 3, 4 };
    bool result = manager->SendMessage(NON_EXISTENT_CONNECTION_NAME, message);
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, SendMessage_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    manager->connections_.push_back(connection);

    std::vector<uint8_t> message = { 1, 2, 3, 4 };
    bool result = manager->SendMessage(DEFAULT_TEST_CONNECTION_NAME, message);
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, SendMessage_003, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    connection->isConnected_ = true;
    manager->connections_.push_back(connection);

    std::vector<uint8_t> message = { 1, 2, 3, 4 };
    bool result = manager->SendMessage(DEFAULT_TEST_CONNECTION_NAME, message);
    EXPECT_TRUE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, SendMessage_004, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    connection->isConnected_ = true;
    manager->connections_.push_back(connection);

    std::vector<uint8_t> message = {};
    bool result = manager->SendMessage(DEFAULT_TEST_CONNECTION_NAME, message);
    EXPECT_TRUE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, CloseConnection_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->CloseConnection("non-existent-connection");
}

HWTEST_F(SoftBusConnectionManagerTest, CloseConnection_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    manager->connections_.push_back(connection);

    manager->CloseConnection("test-connection");

    EXPECT_TRUE(manager->connections_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, ReportConnectionEstablished_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->ReportConnectionEstablished("test-connection");
}

HWTEST_F(SoftBusConnectionManagerTest, ReportConnectionEstablished_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeConnectionStatus(
        [&callbackInvoked](const std::string &name, ConnectionStatus status, const std::string &) {
            if (name == "test-connection" && status == ConnectionStatus::CONNECTED) {
                callbackInvoked = true;
            }
        });

    manager->ReportConnectionEstablished("test-connection");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SoftBusConnectionManagerTest, ReportConnectionClosed_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->ReportConnectionClosed("test-connection", "test-reason");
}

HWTEST_F(SoftBusConnectionManagerTest, ReportConnectionClosed_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    std::string receivedReason;
    auto subscription = manager->SubscribeConnectionStatus([&callbackInvoked, &receivedReason](const std::string &name,
                                                               ConnectionStatus status, const std::string &reason) {
        if (name == "test-connection" && status == ConnectionStatus::DISCONNECTED) {
            callbackInvoked = true;
            receivedReason = reason;
        }
    });

    manager->ReportConnectionClosed("test-connection", "test-reason");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
    EXPECT_EQ(receivedReason, "test-reason");
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBind_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    manager->connections_.push_back(connection);

    manager->HandleBind(100, "test-network-id");
}

HWTEST_F(SoftBusConnectionManagerTest, HandleError_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleError(100, 0);
}

HWTEST_F(SoftBusConnectionManagerTest, HandleError_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    manager->connections_.push_back(connection);

    manager->HandleError(100, 0);

    EXPECT_TRUE(manager->connections_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleShutdown_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleShutdown(100, 0);
}

HWTEST_F(SoftBusConnectionManagerTest, HandleShutdown_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    manager->connections_.push_back(connection);

    manager->HandleShutdown(100, 0);

    EXPECT_TRUE(manager->connections_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    manager->HandleBytes(100, data.data(), data.size());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    manager->connections_.push_back(connection);

    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    manager->HandleBytes(100, data.data(), data.size());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_003, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    manager->connections_.push_back(connection);

    Attributes message;
    message.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test-connection");

    std::vector<uint8_t> data = message.Serialize();
    manager->HandleBytes(100, data.data(), data.size());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_004, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    manager->connections_.push_back(connection);

    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    manager->HandleBytes(100, data.data(), data.size());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_005, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeRawMessage(
        [&callbackInvoked](const std::string &, const std::vector<uint8_t> &data) { callbackInvoked = true; });

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    manager->connections_.push_back(connection);

    Attributes message;
    message.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test-connection");

    std::vector<uint8_t> data = message.Serialize();
    manager->HandleBytes(100, data.data(), data.size());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_006, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeRawMessage(
        [&callbackInvoked](const std::string &, const std::vector<uint8_t> &data) { callbackInvoked = true; });

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    manager->connections_.push_back(connection);

    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    manager->HandleBytes(100, data.data(), data.size());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SoftBusConnectionManagerTest, UnsubscribeRawMessage_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeRawMessage(
        [&callbackInvoked](const std::string &, const std::vector<uint8_t> &) { callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);

    manager->UnsubscribeRawMessage(1);

    EXPECT_TRUE(manager->rawMessageSubscribers_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, UnsubscribeConnectionStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeConnectionStatus(
        [&callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);

    manager->UnsubscribeConnectionStatus(1);

    EXPECT_TRUE(manager->connectionStatusSubscribers_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, UnsubscribeIncomingConnection_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeIncomingConnection(
        [&callbackInvoked](const std::string &, const PhysicalDeviceKey &) { callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);

    manager->UnsubscribeIncomingConnection(1);

    EXPECT_TRUE(manager->incomingConnectionSubscribers_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, Destructor_001, TestSize.Level0)
{
    MockGuard guard;

    {
        auto manager = SoftBusConnectionManager::Create();
        ASSERT_NE(manager, nullptr);
    }
}

HWTEST_F(SoftBusConnectionManagerTest, Destructor_002, TestSize.Level0)
{
    MockGuard guard;

    {
        auto manager = SoftBusConnectionManager::Create();
        ASSERT_NE(manager, nullptr);

        PhysicalDeviceKey key;
        key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        key.deviceId = "test-device";

        auto connection =
            std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
        manager->connections_.push_back(connection);

        manager->serverSocketId_ = 1;
    }
}

HWTEST_F(SoftBusConnectionManagerTest, HandleSoftBusServiceReady_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->serverSocketId_ = 1;

    manager->HandleSoftBusServiceReady();
}

HWTEST_F(SoftBusConnectionManagerTest, HandleSoftBusServiceReady_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleSoftBusServiceReady();
}

HWTEST_F(SoftBusConnectionManagerTest, OpenConnection_001, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection =
        std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key, manager);
    manager->connections_.push_back(connection);

    bool result = manager->OpenConnection("test-connection", key, "network-id");

    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, OpenConnection_002, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });
    ON_CALL(mockSoftBusAdapter_, CreateClientSocket(_, _)).WillByDefault(Return(std::optional<int32_t>(INT32_2)));

    auto softBusAdapter = std::shared_ptr<ISoftBusAdapter>(&mockSoftBusAdapter_, [](ISoftBusAdapter *) {});
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    bool result = manager->OpenConnection("test-connection", key, "network-id");

    EXPECT_TRUE(result);
    EXPECT_FALSE(manager->connections_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleSoftBusServiceUnavailable_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleSoftBusServiceUnavailable();
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
