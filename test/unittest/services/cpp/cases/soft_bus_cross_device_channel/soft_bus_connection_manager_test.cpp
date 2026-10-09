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

#include "mock_device_manager_adapter.h"
#include "mock_guard.h"
#include "mock_soft_bus_adapter.h"

#include "relative_timer.h"
#include "soft_bus_adapter.h"
#include "soft_bus_adapter_manager.h"
#include "soft_bus_channel_common.h"
#include "soft_bus_connection.h"
#include "soft_bus_connection_manager.h"
#include "soft_bus_coordinator_adapter.h"
#include "subscription.h"
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
constexpr const char *TEST_NETWORK_ID = "test-network-id";
constexpr size_t MAX_SOFTBUS_CONNECTIONS = 200;
constexpr uint32_t INBOUND_NAMING_TIMEOUT_MS = 10000;
constexpr uint32_t PENDING_OPEN_MONITOR_INTERVAL_MS = PENDING_ARBITRATION_TIMEOUT_MS / 2;

// MockGuard resets and installs the device-manager and softbus adapter mocks but
// no coordinator adapter, while the connection manager and SoftbusConnection
// consult GetSoftBusCoordinatorAdapter() on Start/OpenConnection/destroy. Each
// test installs this local mock.
class MockSoftBusCoordinatorAdapter : public ISoftBusCoordinatorAdapter {
public:
    MOCK_METHOD(bool, Initialize, (), (override));
    MOCK_METHOD(void, RequestResource,
        (const std::string &, const std::string &, ConnectionMode, ConnectDecisionCallback &&), (override));
    MOCK_METHOD(std::unique_ptr<Subscription>, RegisterDisconnectRequestedCallback, (DisconnectRequestedCallback &&),
        (override));
    MOCK_METHOD(void, AddConnection, (const std::string &, const std::string &), (override));
    MOCK_METHOD(void, RemoveConnection, (const std::string &), (override));
    MOCK_METHOD(void, ReleaseResource, (const std::string &), (override));
};

std::shared_ptr<NiceMock<MockSoftBusCoordinatorAdapter>> InstallCoordinatorMock()
{
    auto coordinator = std::make_shared<NiceMock<MockSoftBusCoordinatorAdapter>>();
    ON_CALL(*coordinator, RequestResource(_, _, _, _))
        .WillByDefault(Invoke([](const std::string &, const std::string &, ConnectionMode,
                                  ConnectDecisionCallback callback) { callback(true); }));
    ON_CALL(*coordinator, RegisterDisconnectRequestedCallback(_))
        .WillByDefault(Return(ByMove(std::make_unique<Subscription>([]() {}))));
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusCoordinatorAdapter(coordinator);
    return coordinator;
}

// Drive the fake RelativeTimer off the MockTimeKeeper and advance both together,
// mirroring cases/fwk_comm/pending_issue_token_manager_test.cpp.
void LinkTimerToTimeKeeper(MockTimeKeeper &timeKeeper)
{
    RelativeTimer::GetInstance().SetTimeProvider(
        [&timeKeeper]() -> uint64_t { return timeKeeper.GetSteadyTimeMs().value_or(0); });
}

void AdvanceAndDrain(MockTimeKeeper &timeKeeper, uint32_t ms)
{
    timeKeeper.AdvanceSteadyTime(ms);
    RelativeTimer::GetInstance().DrainExpiredTasks();
}

class SoftBusConnectionManagerTest : public Test {
protected:
    uint64_t nextGlobalId_ = UINT64_1;
    NiceMock<MockSoftBusAdapter> mockSoftBusAdapter_;
    NiceMock<MockDeviceManagerAdapter> mockDeviceManagerAdapter_;
};

HWTEST_F(SoftBusConnectionManagerTest, Create_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    EXPECT_NE(manager, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, Start_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    bool result = manager->Start();
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, Start_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);
    manager->started_ = true;

    bool result = manager->Start();
    EXPECT_TRUE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeRawMessage_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeRawMessage(
        [callbackInvoked](const std::string &, const std::vector<uint8_t> &) { *callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeRawMessage_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto subscription = manager->SubscribeRawMessage(nullptr);
    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeConnectionStatus_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeConnectionStatus(
        [callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { *callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeConnectionStatus_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto subscription = manager->SubscribeConnectionStatus(nullptr);
    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeIncomingConnection_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeIncomingConnection(
        [callbackInvoked](const std::string &, const PhysicalDeviceKey &) { *callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SubscribeIncomingConnection_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto subscription = manager->SubscribeIncomingConnection(nullptr);
    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusConnectionManagerTest, SendMessage_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    std::vector<uint8_t> message = { 1, 2, 3, 4 };
    bool result = manager->SendMessage(NON_EXISTENT_CONNECTION_NAME, message);
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, SendMessage_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    std::vector<uint8_t> message = { 1, 2, 3, 4 };
    bool result = manager->SendMessage(DEFAULT_TEST_CONNECTION_NAME, message);
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, SendMessage_003, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });
    ON_CALL(mockSoftBusAdapter_, SendBytes(_, _)).WillByDefault(Return(true));

    auto softBusAdapter = std::shared_ptr<ISoftBusAdapter>(&mockSoftBusAdapter_, [](ISoftBusAdapter *) {});
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    connection->isConnected_ = true;
    manager->connections_.push_back(connection);

    std::vector<uint8_t> message = { 1, 2, 3, 4 };
    bool result = manager->SendMessage(DEFAULT_TEST_CONNECTION_NAME, message);
    EXPECT_TRUE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, SendMessage_004, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });
    ON_CALL(mockSoftBusAdapter_, SendBytes(_, _)).WillByDefault(Return(true));

    auto softBusAdapter = std::shared_ptr<ISoftBusAdapter>(&mockSoftBusAdapter_, [](ISoftBusAdapter *) {});
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    connection->isConnected_ = true;
    manager->connections_.push_back(connection);

    std::vector<uint8_t> message = {};
    bool result = manager->SendMessage(DEFAULT_TEST_CONNECTION_NAME, message);
    EXPECT_TRUE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, CloseConnection_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->CloseConnection("non-existent-connection", "test");
}

HWTEST_F(SoftBusConnectionManagerTest, CloseConnection_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    manager->CloseConnection("test-connection", "test");

    EXPECT_TRUE(manager->connections_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, ReportConnectionEstablished_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->ReportConnectionEstablished("test-connection");
}

HWTEST_F(SoftBusConnectionManagerTest, ReportConnectionEstablished_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeConnectionStatus(
        [callbackInvoked](const std::string &name, ConnectionStatus status, const std::string &) {
            if (name == "test-connection" && status == ConnectionStatus::CONNECTED) {
                *callbackInvoked = true;
            }
        });

    manager->ReportConnectionEstablished("test-connection");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackInvoked);
}

HWTEST_F(SoftBusConnectionManagerTest, ReportConnectionClosed_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->ReportConnectionClosed("test-connection", "test-reason");
}

HWTEST_F(SoftBusConnectionManagerTest, ReportConnectionClosed_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto receivedReason = std::make_shared<std::string>();
    auto subscription = manager->SubscribeConnectionStatus(
        [callbackInvoked, receivedReason](const std::string &name, ConnectionStatus status, const std::string &reason) {
            if (name == "test-connection" && status == ConnectionStatus::DISCONNECTED) {
                *callbackInvoked = true;
                *receivedReason = reason;
            }
        });

    manager->ReportConnectionClosed("test-connection", "test-reason");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackInvoked);
    EXPECT_EQ(*receivedReason, "test-reason");
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBind_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    manager->HandleBind(100, "test-network-id");
}

HWTEST_F(SoftBusConnectionManagerTest, HandleError_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleError(100, 0);
}

HWTEST_F(SoftBusConnectionManagerTest, HandleError_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    manager->HandleError(100, 0);

    EXPECT_TRUE(manager->connections_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleShutdown_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleShutdown(100, 0);
}

HWTEST_F(SoftBusConnectionManagerTest, HandleShutdown_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    manager->HandleShutdown(100, 0);

    EXPECT_TRUE(manager->connections_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    manager->HandleBytes(100, data.data(), data.size());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    manager->HandleBytes(100, data.data(), data.size());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_003, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    Attributes message;
    message.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test-connection");

    std::vector<uint8_t> data = message.Serialize();
    manager->HandleBytes(100, data.data(), data.size());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_004, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    manager->HandleBytes(100, data.data(), data.size());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_005, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeRawMessage(
        [callbackInvoked](const std::string &, const std::vector<uint8_t> &data) { *callbackInvoked = true; });

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    Attributes message;
    message.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test-connection");

    std::vector<uint8_t> data = message.Serialize();
    manager->HandleBytes(100, data.data(), data.size());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackInvoked);
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBytes_006, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeRawMessage(
        [callbackInvoked](const std::string &, const std::vector<uint8_t> &data) { *callbackInvoked = true; });

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    manager->HandleBytes(100, data.data(), data.size());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackInvoked);
}

HWTEST_F(SoftBusConnectionManagerTest, UnsubscribeRawMessage_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeRawMessage(
        [callbackInvoked](const std::string &, const std::vector<uint8_t> &) { *callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);

    manager->UnsubscribeRawMessage(1);

    EXPECT_TRUE(manager->rawMessageSubscribers_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, UnsubscribeConnectionStatus_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeConnectionStatus(
        [callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { *callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);

    manager->UnsubscribeConnectionStatus(1);

    EXPECT_TRUE(manager->connectionStatusSubscribers_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, UnsubscribeIncomingConnection_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    auto callbackInvoked = std::make_shared<bool>(false);
    auto subscription = manager->SubscribeIncomingConnection(
        [callbackInvoked](const std::string &, const PhysicalDeviceKey &) { *callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);

    manager->UnsubscribeIncomingConnection(1);

    EXPECT_TRUE(manager->incomingConnectionSubscribers_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, Destructor_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    {
        auto manager = SoftBusConnectionManager::Create();
        ASSERT_NE(manager, nullptr);
    }
}

HWTEST_F(SoftBusConnectionManagerTest, Destructor_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    ON_CALL(mockSoftBusAdapter_, ShutdownSocket(_)).WillByDefault(Return());

    auto softBusAdapter = std::shared_ptr<ISoftBusAdapter>(&mockSoftBusAdapter_, [](ISoftBusAdapter *) {});
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    {
        auto manager = SoftBusConnectionManager::Create();
        ASSERT_NE(manager, nullptr);

        PhysicalDeviceKey key;
        key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        key.deviceId = "test-device";

        auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
            TEST_NETWORK_ID, manager);
        manager->connections_.push_back(connection);

        manager->serverSocketId_ = 1;
    }
}

HWTEST_F(SoftBusConnectionManagerTest, HandleSoftBusServiceReady_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    ON_CALL(mockSoftBusAdapter_, CreateServerSocket()).WillByDefault(Return(std::optional<int32_t>(1)));

    auto softBusAdapter = std::shared_ptr<ISoftBusAdapter>(&mockSoftBusAdapter_, [](ISoftBusAdapter *) {});
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->serverSocketId_ = 1;

    manager->HandleSoftBusServiceReady();
}

HWTEST_F(SoftBusConnectionManagerTest, HandleSoftBusServiceReady_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    ON_CALL(mockSoftBusAdapter_, CreateServerSocket()).WillByDefault(Return(std::optional<int32_t>(1)));

    auto softBusAdapter = std::shared_ptr<ISoftBusAdapter>(&mockSoftBusAdapter_, [](ISoftBusAdapter *) {});
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleSoftBusServiceReady();
}

HWTEST_F(SoftBusConnectionManagerTest, OpenConnection_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    bool result = manager->OpenConnection("test-connection", ConnectionMode::BACKGROUND, key, "network-id");

    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusConnectionManagerTest, OpenConnection_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });
    ON_CALL(mockSoftBusAdapter_, CreateClientSocket(_, _)).WillByDefault(Return(std::optional<int32_t>(INT32_2)));

    auto softBusAdapter = std::shared_ptr<ISoftBusAdapter>(&mockSoftBusAdapter_, [](ISoftBusAdapter *) {});
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    bool result = manager->OpenConnection("test-connection", ConnectionMode::BACKGROUND, key, "network-id");

    EXPECT_TRUE(result);
    // The socket is created in the posted arbitration continuation.
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_FALSE(manager->connections_.empty());
}

// The connection registers with the coordinator only when the socket reports connected
// (HandleOutboundConnected), mirroring the inbound path; until then only the resource holding
// list carries the name.
HWTEST_F(SoftBusConnectionManagerTest, OpenConnection_RegistersOnOutboundConnected, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });
    ON_CALL(mockSoftBusAdapter_, CreateClientSocket(_, _)).WillByDefault(Return(std::optional<int32_t>(INT32_2)));

    auto softBusAdapter = std::shared_ptr<ISoftBusAdapter>(&mockSoftBusAdapter_, [](ISoftBusAdapter *) {});
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    std::vector<std::string> added;
    std::vector<std::string> removed;
    ON_CALL(*coordinator, AddConnection(_, _))
        .WillByDefault(Invoke([&added](const std::string &name, const std::string &) { added.push_back(name); }));
    ON_CALL(*coordinator, RemoveConnection(_)).WillByDefault(Invoke([&removed](const std::string &name) {
        removed.push_back(name);
    }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    EXPECT_TRUE(
        manager->OpenConnection(DEFAULT_TEST_CONNECTION_NAME, ConnectionMode::BACKGROUND, key, TEST_NETWORK_ID));
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_FALSE(manager->connections_.empty());
    // The socket exists but has not reported connected yet: no occupancy registration.
    EXPECT_TRUE(added.empty());

    manager->HandleBind(INT32_2, TEST_NETWORK_ID);
    EXPECT_EQ(added, std::vector<std::string> { DEFAULT_TEST_CONNECTION_NAME });
    EXPECT_TRUE(removed.empty());
}

// A grant that never becomes a connection is released, so the coordinator does not hold the
// resource forever.
HWTEST_F(SoftBusConnectionManagerTest, OpenConnection_ReleasesGrant_WhenSocketCreationFails, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });
    ON_CALL(mockSoftBusAdapter_, CreateClientSocket(_, _)).WillByDefault(Return(std::nullopt));

    auto softBusAdapter = std::shared_ptr<ISoftBusAdapter>(&mockSoftBusAdapter_, [](ISoftBusAdapter *) {});
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    std::vector<std::string> added;
    std::vector<std::string> released;
    ON_CALL(*coordinator, AddConnection(_, _))
        .WillByDefault(Invoke([&added](const std::string &name, const std::string &) { added.push_back(name); }));
    ON_CALL(*coordinator, ReleaseResource(_)).WillByDefault(Invoke([&released](const std::string &name) {
        released.push_back(name);
    }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    EXPECT_TRUE(
        manager->OpenConnection(DEFAULT_TEST_CONNECTION_NAME, ConnectionMode::BACKGROUND, key, TEST_NETWORK_ID));
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    // The socket fails before the late Add, so occupancy is never touched and the grant returns
    // through ReleaseResource.
    EXPECT_TRUE(added.empty());
    EXPECT_EQ(released, std::vector<std::string> { DEFAULT_TEST_CONNECTION_NAME });
    EXPECT_TRUE(manager->connections_.empty());
}

// A grant that outlives the open it was asked for is returned through the same release call,
// even though no connection was ever registered under its name.
HWTEST_F(SoftBusConnectionManagerTest, HandleCanConnectResult_ReleasesGrant_WhenOpenCancelled, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    ConnectDecisionCallback settle;
    ON_CALL(*coordinator, RequestResource(_, _, _, _))
        .WillByDefault(Invoke([&settle](const std::string &, const std::string &, ConnectionMode,
                                  ConnectDecisionCallback callback) { settle = std::move(callback); }));

    std::vector<std::string> added;
    std::vector<std::string> released;
    ON_CALL(*coordinator, AddConnection(_, _))
        .WillByDefault(Invoke([&added](const std::string &name, const std::string &) { added.push_back(name); }));
    ON_CALL(*coordinator, ReleaseResource(_)).WillByDefault(Invoke([&released](const std::string &name) {
        released.push_back(name);
    }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    EXPECT_TRUE(
        manager->OpenConnection(DEFAULT_TEST_CONNECTION_NAME, ConnectionMode::BACKGROUND, key, TEST_NETWORK_ID));
    manager->CloseConnection(DEFAULT_TEST_CONNECTION_NAME, "cancelled");
    ASSERT_NE(settle, nullptr);
    settle(true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_TRUE(added.empty());
    EXPECT_EQ(released, std::vector<std::string> { DEFAULT_TEST_CONNECTION_NAME });
    EXPECT_TRUE(manager->connections_.empty());
}

HWTEST_F(SoftBusConnectionManagerTest, HandleSoftBusServiceUnavailable_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleSoftBusServiceUnavailable();
}

HWTEST_F(SoftBusConnectionManagerTest, OpenConnection_RejectsWhenMaxConnectionsReached, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });
    ON_CALL(mockSoftBusAdapter_, CreateClientSocket(_, _)).WillByDefault(Return(std::optional<int32_t>(INT32_2)));

    auto softBusAdapter = std::shared_ptr<ISoftBusAdapter>(&mockSoftBusAdapter_, [](ISoftBusAdapter *) {});
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    // Fill connections_ up to the limit.
    for (size_t i = 0; i < MAX_SOFTBUS_CONNECTIONS; ++i) {
        int32_t socketId = static_cast<int32_t>(i + 100);
        auto connection =
            std::make_shared<SoftbusConnection>(socketId, "conn_" + std::to_string(i), key, TEST_NETWORK_ID, manager);
        manager->connections_.push_back(connection);
    }
    ASSERT_EQ(manager->connections_.size(), MAX_SOFTBUS_CONNECTIONS);

    // The next OpenConnection should be rejected.
    bool result = manager->OpenConnection("overflow-connection", ConnectionMode::BACKGROUND, key, "network-id");
    EXPECT_FALSE(result);
    EXPECT_EQ(manager->connections_.size(), MAX_SOFTBUS_CONNECTIONS);
}

// A coordinator denial is reported as DISCONNECTED(coordinator_rejected) before any socket is created.
HWTEST_F(SoftBusConnectionManagerTest, OpenConnection_ReportsCoordinatorRejected_WhenDenied, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();
    ON_CALL(*coordinator, RequestResource(_, _, _, _))
        .WillByDefault(Invoke([](const std::string &, const std::string &, ConnectionMode,
                                  ConnectDecisionCallback callback) { callback(false); }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    ConnectionStatus reportedStatus = ConnectionStatus::CONNECTED;
    std::string reportedReason;
    auto subscription =
        manager->SubscribeConnectionStatus([&reportedStatus, &reportedReason](const std::string &connectionName,
                                               ConnectionStatus status, const std::string &reason) {
            reportedStatus = status;
            reportedReason = reason;
        });
    ASSERT_NE(subscription, nullptr);

    bool result = manager->OpenConnection("test-connection", ConnectionMode::BACKGROUND, key, "network-id");
    // The open is accepted synchronously; the denial arrives through the status event.
    EXPECT_TRUE(result);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(reportedStatus, ConnectionStatus::DISCONNECTED);
    EXPECT_EQ(reportedReason, REASON_COORDINATOR_REJECTED);
    EXPECT_TRUE(manager->connections_.empty());
}

// The disconnect-requested callback registered on Start closes the connections of that networkId.
HWTEST_F(SoftBusConnectionManagerTest, DisconnectRequested_ClosesConnectionsOfMatchingNetworkId, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();

    DisconnectRequestedCallback disconnectRequested;
    ON_CALL(*coordinator, RegisterDisconnectRequestedCallback(_))
        .WillByDefault(Invoke([&disconnectRequested](DisconnectRequestedCallback &&callback) {
            disconnectRequested = std::move(callback);
            return nullptr;
        }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->Start();
    ASSERT_NE(disconnectRequested, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto victim = std::make_shared<SoftbusConnection>(101, "victim-connection", key, "network-a", manager);
    manager->connections_.push_back(victim);
    auto survivor = std::make_shared<SoftbusConnection>(102, "survivor-connection", key, "network-b", manager);
    manager->connections_.push_back(survivor);

    disconnectRequested("network-a");

    EXPECT_EQ(manager->connections_.size(), 1);
    EXPECT_EQ(manager->connections_.front()->GetConnectionName(), "survivor-connection");
}

// The matching networkId's unnamed inbound is closed by socketId: a name-keyed close
// would find the other device's unnamed inbound first and close that one instead.
HWTEST_F(SoftBusConnectionManagerTest, DisconnectRequested_ClosesUnnamedInboundOfMatchingNetworkId, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    DisconnectRequestedCallback disconnectRequested;
    ON_CALL(*coordinator, RegisterDisconnectRequestedCallback(_))
        .WillByDefault(Invoke([&disconnectRequested](DisconnectRequestedCallback &&callback) {
            disconnectRequested = std::move(callback);
            return nullptr;
        }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->Start();
    ASSERT_NE(disconnectRequested, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto bystander = std::make_shared<SoftbusConnection>(201, key, "network-b", manager);
    manager->connections_.push_back(bystander);
    auto target = std::make_shared<SoftbusConnection>(202, key, "network-a", manager);
    manager->connections_.push_back(target);

    disconnectRequested("network-a");

    ASSERT_EQ(manager->connections_.size(), 1);
    EXPECT_EQ(manager->connections_.front()->GetSocketId(), 201);
}

// A disconnect request also revokes that device's pending opens, so a late
// arbitration allow can no longer create the socket.
HWTEST_F(SoftBusConnectionManagerTest, DisconnectRequested_RevokesPendingOpenOfMatchingNetworkId, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    DisconnectRequestedCallback disconnectRequested;
    ON_CALL(*coordinator, RegisterDisconnectRequestedCallback(_))
        .WillByDefault(Invoke([&disconnectRequested](DisconnectRequestedCallback &&callback) {
            disconnectRequested = std::move(callback);
            return nullptr;
        }));

    ConnectDecisionCallback pendingAllow;
    ON_CALL(*coordinator, RequestResource(_, _, _, _))
        .WillByDefault(Invoke([&pendingAllow](const std::string &, const std::string &, ConnectionMode,
                                  ConnectDecisionCallback callback) { pendingAllow = std::move(callback); }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->Start();
    ASSERT_NE(disconnectRequested, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    ConnectionStatus reportedStatus = ConnectionStatus::CONNECTED;
    std::string reportedReason;
    auto subscription = manager->SubscribeConnectionStatus(
        [&reportedStatus, &reportedReason](const std::string &, ConnectionStatus status, const std::string &reason) {
            reportedStatus = status;
            reportedReason = reason;
        });
    ASSERT_NE(subscription, nullptr);

    ASSERT_TRUE(manager->OpenConnection("pending-connection", ConnectionMode::BACKGROUND, key, "network-a"));
    ASSERT_NE(pendingAllow, nullptr);
    ASSERT_EQ(manager->pendingOpens_.size(), 1);

    disconnectRequested("network-a");
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_TRUE(manager->pendingOpens_.empty());
    EXPECT_EQ(reportedStatus, ConnectionStatus::DISCONNECTED);
    EXPECT_EQ(reportedReason, REASON_DISCONNECT_REQUESTED);

    // The allow arriving after the revocation must not create a socket.
    pendingAllow(true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(manager->connections_.empty());
}

// The pending open of another network survives the disconnect request and
// still completes on its own allow.
HWTEST_F(SoftBusConnectionManagerTest, DisconnectRequested_KeepsPendingOpenOfOtherNetwork, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    DisconnectRequestedCallback disconnectRequested;
    ON_CALL(*coordinator, RegisterDisconnectRequestedCallback(_))
        .WillByDefault(Invoke([&disconnectRequested](DisconnectRequestedCallback &&callback) {
            disconnectRequested = std::move(callback);
            return nullptr;
        }));

    std::map<std::string, ConnectDecisionCallback> pendingAllows;
    ON_CALL(*coordinator, RequestResource(_, _, _, _))
        .WillByDefault(
            Invoke([&pendingAllows](const std::string &connectionName, const std::string &, ConnectionMode,
                       ConnectDecisionCallback callback) { pendingAllows[connectionName] = std::move(callback); }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->Start();
    ASSERT_NE(disconnectRequested, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    ASSERT_TRUE(manager->OpenConnection("conn-network-a", ConnectionMode::BACKGROUND, key, "network-a"));
    ASSERT_TRUE(manager->OpenConnection("conn-network-b", ConnectionMode::BACKGROUND, key, "network-b"));
    ASSERT_EQ(manager->pendingOpens_.size(), 2);

    disconnectRequested("network-a");
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    ASSERT_EQ(manager->pendingOpens_.size(), 1);
    EXPECT_EQ(manager->pendingOpens_.count("conn-network-b"), 1);

    auto it = pendingAllows.find("conn-network-b");
    ASSERT_NE(it, pendingAllows.end());
    it->second(true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    ASSERT_EQ(manager->connections_.size(), 1);
    EXPECT_EQ(manager->connections_.front()->GetConnectionName(), "conn-network-b");
}

// A pending open that is never arbitrated is dropped by its own monitor tick —
// not only lazily on the next OpenConnection — and surfaces as a close event,
// so the caller is unblocked before its own request timeout.
HWTEST_F(SoftBusConnectionManagerTest, PendingOpenMonitor_ReportsClosed_OnArbitrationTimeout, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    ConnectDecisionCallback pendingAllow;
    ON_CALL(*coordinator, RequestResource(_, _, _, _))
        .WillByDefault(Invoke([&pendingAllow](const std::string &, const std::string &, ConnectionMode,
                                  ConnectDecisionCallback callback) { pendingAllow = std::move(callback); }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->Start();

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    ConnectionStatus reportedStatus = ConnectionStatus::CONNECTED;
    std::string reportedReason;
    auto subscription = manager->SubscribeConnectionStatus(
        [&reportedStatus, &reportedReason](const std::string &, ConnectionStatus status, const std::string &reason) {
            reportedStatus = status;
            reportedReason = reason;
        });
    ASSERT_NE(subscription, nullptr);

    ASSERT_TRUE(manager->OpenConnection("pending-connection", ConnectionMode::BACKGROUND, key, TEST_NETWORK_ID));
    ASSERT_NE(manager->pendingOpenSubscription_, nullptr);

    AdvanceAndDrain(guard.GetTimeKeeper(), PENDING_ARBITRATION_TIMEOUT_MS);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_TRUE(manager->pendingOpens_.empty());
    EXPECT_EQ(manager->pendingOpenSubscription_, nullptr);
    EXPECT_EQ(reportedStatus, ConnectionStatus::DISCONNECTED);
    EXPECT_EQ(reportedReason, REASON_COORDINATOR_TIMEOUT);

    // The allow arriving after the sweep must not create a socket.
    pendingAllow(true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(manager->connections_.empty());
}

// A deny racing the sweep (every real arbitration timeout produces one: the manager sweep
// settles first, the coordinator sweep denies right after) must be dropped silently — a
// second DISCONNECTED would drift the settled TIMEOUT into COORDINATOR_REJECTED.
HWTEST_F(SoftBusConnectionManagerTest, PendingOpenMonitor_LateDeny_AfterArbitrationTimeout_NoSecondReport,
    TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    ConnectDecisionCallback pendingAllow;
    ON_CALL(*coordinator, RequestResource(_, _, _, _))
        .WillByDefault(Invoke([&pendingAllow](const std::string &, const std::string &, ConnectionMode,
                                  ConnectDecisionCallback callback) { pendingAllow = std::move(callback); }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->Start();

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    int32_t disconnectCount = 0;
    std::string reportedReason;
    auto subscription = manager->SubscribeConnectionStatus(
        [&disconnectCount, &reportedReason](const std::string &, ConnectionStatus status, const std::string &reason) {
            if (status == ConnectionStatus::DISCONNECTED) {
                ++disconnectCount;
                reportedReason = reason;
            }
        });
    ASSERT_NE(subscription, nullptr);

    ASSERT_TRUE(manager->OpenConnection("pending-connection", ConnectionMode::BACKGROUND, key, TEST_NETWORK_ID));
    AdvanceAndDrain(guard.GetTimeKeeper(), PENDING_ARBITRATION_TIMEOUT_MS);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(disconnectCount, 1);
    EXPECT_EQ(reportedReason, REASON_COORDINATOR_TIMEOUT);

    pendingAllow(false);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(disconnectCount, 1);
    EXPECT_EQ(reportedReason, REASON_COORDINATOR_TIMEOUT);
    EXPECT_TRUE(manager->connections_.empty());
}

// The allow counterpart of the late deny above: the grant must be returned to the
// coordinator, but the already-swept open must not be reported a second time.
HWTEST_F(SoftBusConnectionManagerTest, PendingOpenMonitor_LateAllow_AfterArbitrationTimeout_NoSecondReport,
    TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    ConnectDecisionCallback pendingAllow;
    ON_CALL(*coordinator, RequestResource(_, _, _, _))
        .WillByDefault(Invoke([&pendingAllow](const std::string &, const std::string &, ConnectionMode,
                                  ConnectDecisionCallback callback) { pendingAllow = std::move(callback); }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    int32_t releaseCount = 0;
    EXPECT_CALL(*coordinator, ReleaseResource(_)).WillRepeatedly(Invoke([&releaseCount](const std::string &) {
        ++releaseCount;
    }));

    manager->Start();

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    int32_t disconnectCount = 0;
    std::string reportedReason;
    auto subscription = manager->SubscribeConnectionStatus(
        [&disconnectCount, &reportedReason](const std::string &, ConnectionStatus status, const std::string &reason) {
            if (status == ConnectionStatus::DISCONNECTED) {
                ++disconnectCount;
                reportedReason = reason;
            }
        });
    ASSERT_NE(subscription, nullptr);

    ASSERT_TRUE(manager->OpenConnection("pending-connection", ConnectionMode::BACKGROUND, key, TEST_NETWORK_ID));
    AdvanceAndDrain(guard.GetTimeKeeper(), PENDING_ARBITRATION_TIMEOUT_MS);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(disconnectCount, 1);
    EXPECT_EQ(reportedReason, REASON_COORDINATOR_TIMEOUT);

    pendingAllow(true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(releaseCount, 1);
    EXPECT_EQ(disconnectCount, 1);
    EXPECT_EQ(reportedReason, REASON_COORDINATOR_TIMEOUT);
    EXPECT_TRUE(manager->connections_.empty());
}

// A clock rollback (request time ahead of now) underflows SafeSub; the anomaly is
// treated as a timeout so the pending open is reclaimed instead of leaking.
HWTEST_F(SoftBusConnectionManagerTest, PendingOpenMonitor_Drops_OnClockRollback, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    ConnectDecisionCallback pendingAllow;
    ON_CALL(*coordinator, RequestResource(_, _, _, _))
        .WillByDefault(Invoke([&pendingAllow](const std::string &, const std::string &, ConnectionMode,
                                  ConnectDecisionCallback callback) { pendingAllow = std::move(callback); }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->Start();

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    ConnectionStatus reportedStatus = ConnectionStatus::CONNECTED;
    std::string reportedReason;
    auto subscription = manager->SubscribeConnectionStatus(
        [&reportedStatus, &reportedReason](const std::string &, ConnectionStatus status, const std::string &reason) {
            reportedStatus = status;
            reportedReason = reason;
        });
    ASSERT_NE(subscription, nullptr);

    guard.GetTimeKeeper().SetSteadyTime(5000);
    ASSERT_TRUE(manager->OpenConnection("pending-connection", ConnectionMode::BACKGROUND, key, TEST_NETWORK_ID));

    // Simulate a clock rollback: request time ahead of now -> SafeSub underflows to nullopt.
    guard.GetTimeKeeper().SetSteadyTime(1000);
    manager->SweepTimedOutPendingOpens();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(manager->pendingOpens_.size(), 0);
    EXPECT_EQ(manager->pendingOpenSubscription_, nullptr);
    EXPECT_EQ(reportedStatus, ConnectionStatus::DISCONNECTED);
    EXPECT_EQ(reportedReason, REASON_COORDINATOR_TIMEOUT);

    // The allow arriving after the sweep must not create a socket.
    pendingAllow(true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(manager->connections_.empty());
}

// The monitor keeps ticking until its own sweep observes an empty table, then stops.
HWTEST_F(SoftBusConnectionManagerTest, PendingOpenMonitor_Stops_AfterLastPendingSettles, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->Start();

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    // InstallCoordinatorMock answers allow immediately, so the pending settles by itself.
    ASSERT_TRUE(manager->OpenConnection("pending-connection", ConnectionMode::BACKGROUND, key, TEST_NETWORK_ID));
    ASSERT_NE(manager->pendingOpenSubscription_, nullptr);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(manager->pendingOpens_.empty());
    EXPECT_NE(manager->pendingOpenSubscription_, nullptr);

    AdvanceAndDrain(guard.GetTimeKeeper(), PENDING_OPEN_MONITOR_INTERVAL_MS);
    EXPECT_EQ(manager->pendingOpenSubscription_, nullptr);
}

// Connections filled up while an open was pending arbitration: the late allow
// is settled as max_connections_reached instead of creating a socket.
HWTEST_F(SoftBusConnectionManagerTest, OpenConnection_ReportsMaxConnectionsReached_WhenFilledDuringArbitration,
    TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    ConnectDecisionCallback pendingAllow;
    ON_CALL(*coordinator, RequestResource(_, _, _, _))
        .WillByDefault(Invoke([&pendingAllow](const std::string &, const std::string &, ConnectionMode,
                                  ConnectDecisionCallback callback) { pendingAllow = std::move(callback); }));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    ConnectionStatus reportedStatus = ConnectionStatus::CONNECTED;
    std::string reportedReason;
    auto subscription = manager->SubscribeConnectionStatus(
        [&reportedStatus, &reportedReason](const std::string &, ConnectionStatus status, const std::string &reason) {
            reportedStatus = status;
            reportedReason = reason;
        });
    ASSERT_NE(subscription, nullptr);

    ASSERT_TRUE(manager->OpenConnection("pending-connection", ConnectionMode::BACKGROUND, key, TEST_NETWORK_ID));
    ASSERT_NE(pendingAllow, nullptr);
    ASSERT_EQ(manager->pendingOpens_.size(), 1);

    for (size_t i = 0; i < MAX_SOFTBUS_CONNECTIONS; ++i) {
        int32_t socketId = static_cast<int32_t>(i + 300);
        auto connection =
            std::make_shared<SoftbusConnection>(socketId, "conn_" + std::to_string(i), key, TEST_NETWORK_ID, manager);
        manager->connections_.push_back(connection);
    }
    ASSERT_EQ(manager->connections_.size(), MAX_SOFTBUS_CONNECTIONS);

    pendingAllow(true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(manager->connections_.size(), MAX_SOFTBUS_CONNECTIONS);
    EXPECT_TRUE(manager->pendingOpens_.empty());
    EXPECT_EQ(reportedStatus, ConnectionStatus::DISCONNECTED);
    EXPECT_EQ(reportedReason, REASON_MAX_CONNECTIONS_REACHED);
}

// A client-socket failure on the allowed open is settled as create_socket_failed.
HWTEST_F(SoftBusConnectionManagerTest, OpenConnection_ReportsCreateSocketFailed_WhenClientSocketFails, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    ON_CALL(guard.GetSoftBusAdapter(), CreateClientSocket(_, _))
        .WillByDefault(Return(std::optional<int32_t>(std::nullopt)));

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    ConnectionStatus reportedStatus = ConnectionStatus::CONNECTED;
    std::string reportedReason;
    auto subscription = manager->SubscribeConnectionStatus(
        [&reportedStatus, &reportedReason](const std::string &, ConnectionStatus status, const std::string &reason) {
            reportedStatus = status;
            reportedReason = reason;
        });
    ASSERT_NE(subscription, nullptr);

    // InstallCoordinatorMock answers allow immediately.
    ASSERT_TRUE(manager->OpenConnection("pending-connection", ConnectionMode::BACKGROUND, key, TEST_NETWORK_ID));

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_TRUE(manager->connections_.empty());
    EXPECT_TRUE(manager->pendingOpens_.empty());
    EXPECT_EQ(reportedStatus, ConnectionStatus::DISCONNECTED);
    EXPECT_EQ(reportedReason, REASON_CREATE_SOCKET_FAILED);
}

HWTEST_F(SoftBusConnectionManagerTest, HandleBind_RejectsWhenMaxConnectionsReached, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    // Fill connections_ up to the limit.
    for (size_t i = 0; i < MAX_SOFTBUS_CONNECTIONS; ++i) {
        int32_t socketId = static_cast<int32_t>(i + 100);
        auto connection =
            std::make_shared<SoftbusConnection>(socketId, "conn_" + std::to_string(i), key, TEST_NETWORK_ID, manager);
        manager->connections_.push_back(connection);
    }
    ASSERT_EQ(manager->connections_.size(), MAX_SOFTBUS_CONNECTIONS);

    // The inbound HandleBind should be rejected.
    int32_t inboundSocketId = 999;
    manager->HandleBind(inboundSocketId, "peer-network-id");

    // No new connection should be added.
    EXPECT_EQ(manager->connections_.size(), MAX_SOFTBUS_CONNECTIONS);
}

// An unnamed inbound connection causes the periodic naming monitor to start.
HWTEST_F(SoftBusConnectionManagerTest, CheckNamingMonitor_StartsTimer_WhenUnnamedInboundExists, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";
    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    manager->CheckNamingMonitor();

    EXPECT_NE(manager->namingMonitorTimerSubscription_, nullptr);
}

// No unnamed inbound -> the monitor must not be (re)started.
HWTEST_F(SoftBusConnectionManagerTest, CheckNamingMonitor_NoTimer_WhenNoUnnamedInbound, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    // Empty connections_.
    manager->CheckNamingMonitor();
    EXPECT_EQ(manager->namingMonitorTimerSubscription_, nullptr);

    // Only a named outbound connection.
    auto outbound = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager);
    manager->connections_.push_back(outbound);
    manager->CheckNamingMonitor();
    EXPECT_EQ(manager->namingMonitorTimerSubscription_, nullptr);

    // Only an inbound connection that already received its name.
    auto inbound = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID + 1, key, TEST_NETWORK_ID, manager);
    inbound->SetConnectionName("named-inbound");
    manager->connections_.push_back(inbound);
    manager->CheckNamingMonitor();
    EXPECT_EQ(manager->namingMonitorTimerSubscription_, nullptr);
}

// Once the only unnamed inbound gets its name, the monitor stops.
HWTEST_F(SoftBusConnectionManagerTest, CheckNamingMonitor_StopsTimer_WhenUnnamedGetsName, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";
    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    manager->CheckNamingMonitor();
    ASSERT_NE(manager->namingMonitorTimerSubscription_, nullptr);

    connection->HandleInboundConnected("named-now");
    manager->CheckNamingMonitor();

    EXPECT_EQ(manager->namingMonitorTimerSubscription_, nullptr);
}

// Removing the last unnamed inbound stops the monitor.
HWTEST_F(SoftBusConnectionManagerTest, CheckNamingMonitor_StopsTimer_OnRemoveLastUnnamed, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";
    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    manager->CheckNamingMonitor();
    ASSERT_NE(manager->namingMonitorTimerSubscription_, nullptr);

    manager->RemoveSocket(DEFAULT_TEST_SOCKET_ID, "test");

    EXPECT_TRUE(manager->connections_.empty());
    EXPECT_EQ(manager->namingMonitorTimerSubscription_, nullptr);
}

// An unnamed inbound whose age exceeds the timeout is force-closed by the monitor tick.
HWTEST_F(SoftBusConnectionManagerTest, HandleNamingMonitorTimer_ClosesExpired_AfterTimeout, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    // Accepted at steady time 0 -> acceptTimeMs = 0.
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";
    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    manager->CheckNamingMonitor();
    ASSERT_NE(manager->namingMonitorTimerSubscription_, nullptr);

    // Advance past the timeout; the single periodic tick fires the monitor.
    AdvanceAndDrain(guard.GetTimeKeeper(), INBOUND_NAMING_TIMEOUT_MS);

    EXPECT_TRUE(manager->connections_.empty());
    EXPECT_EQ(manager->namingMonitorTimerSubscription_, nullptr);
}

// A clock rollback underflows SafeSub in the naming monitor; the anomaly settles as expired —
// same semantics as the pending-open sweep — instead of skipping the connection.
HWTEST_F(SoftBusConnectionManagerTest, HandleNamingMonitorTimer_ClosesExpired_OnClockRollback, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    // Accepted at steady time 5000 -> acceptTimeMs = 5000.
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";
    guard.GetTimeKeeper().SetSteadyTime(5000);
    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    manager->CheckNamingMonitor();
    ASSERT_NE(manager->namingMonitorTimerSubscription_, nullptr);

    // Simulate a clock rollback: accept time ahead of now -> SafeSub underflows to nullopt.
    guard.GetTimeKeeper().SetSteadyTime(1000);
    manager->HandleNamingMonitorTimer();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_TRUE(manager->connections_.empty());
    EXPECT_EQ(manager->namingMonitorTimerSubscription_, nullptr);
}

// An unnamed inbound below the timeout age survives the monitor tick.
HWTEST_F(SoftBusConnectionManagerTest, HandleNamingMonitorTimer_KeepsConnection_BeforeTimeout, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";
    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager);
    manager->connections_.push_back(connection);

    manager->CheckNamingMonitor();
    ASSERT_NE(manager->namingMonitorTimerSubscription_, nullptr);

    // Age (9999 - 0) is below the 10000ms threshold -> not closed.
    guard.GetTimeKeeper().SetSteadyTime(9999);
    manager->HandleNamingMonitorTimer();

    EXPECT_EQ(manager->connections_.size(), 1);
    EXPECT_NE(manager->namingMonitorTimerSubscription_, nullptr);
}

// HandleBind accepts an inbound and starts the naming monitor end-to-end.
HWTEST_F(SoftBusConnectionManagerTest, HandleBind_StartsNamingMonitor, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    // MockGuard defaults: GetUdidByNetworkId -> "test-udid", so HandleBind accepts the inbound.
    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleBind(200, "peer-network-id");

    EXPECT_EQ(manager->connections_.size(), 1);
    EXPECT_NE(manager->namingMonitorTimerSubscription_, nullptr);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
