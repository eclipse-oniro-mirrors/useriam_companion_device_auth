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

#include "soft_bus_adapter_manager.h"
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

constexpr uint64_t UINT64_1 = 1;
constexpr int32_t DEFAULT_TEST_SOCKET_ID = 100;
constexpr const char *DEFAULT_TEST_CONNECTION_NAME = "test-connection";
constexpr const char *TEST_DEVICE_ID = "test-device";
constexpr const char *TEST_NETWORK_ID = "test-network-id";

// MockGuard resets and installs the device-manager and softbus adapter mocks but
// no coordinator adapter, while SoftbusConnection reports named connections to
// the coordinator on connect/destruct. Each test installs this local mock.
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
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusCoordinatorAdapter(coordinator);
    return coordinator;
}

class SoftbusConnectionTest : public Test {
protected:
    uint64_t nextGlobalId_ = UINT64_1;
    std::shared_ptr<SoftBusConnectionManager> manager_;
};

HWTEST_F(SoftbusConnectionTest, Constructor_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    EXPECT_EQ(connection->GetSocketId(), DEFAULT_TEST_SOCKET_ID);
    EXPECT_EQ(connection->GetConnectionName(), DEFAULT_TEST_CONNECTION_NAME);
    EXPECT_EQ(connection->GetPhysicalDeviceKey().deviceId, TEST_DEVICE_ID);
    EXPECT_EQ(connection->GetNetworkId(), TEST_NETWORK_ID);
    EXPECT_FALSE(connection->IsConnected());
    EXPECT_FALSE(connection->IsInbound());
}

HWTEST_F(SoftbusConnectionTest, Constructor_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    EXPECT_EQ(connection->GetSocketId(), DEFAULT_TEST_SOCKET_ID);
    EXPECT_TRUE(connection->GetConnectionName().empty());
    EXPECT_EQ(connection->GetPhysicalDeviceKey().deviceId, TEST_DEVICE_ID);
    EXPECT_EQ(connection->GetNetworkId(), TEST_NETWORK_ID);
    EXPECT_FALSE(connection->IsConnected());
    EXPECT_TRUE(connection->IsInbound());
}

HWTEST_F(SoftbusConnectionTest, SetCloseReason_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    connection->SetCloseReason("test-reason");

    EXPECT_EQ(connection->closeReason_, "test-reason");
}

HWTEST_F(SoftbusConnectionTest, SetConnectionName_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    connection->SetConnectionName("new-connection");
    EXPECT_EQ(connection->GetConnectionName(), "new-connection");
}

HWTEST_F(SoftbusConnectionTest, HandleOutboundConnected_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
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

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    connection->HandleOutboundConnected();
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(connection->IsConnected());
    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SoftbusConnectionTest, HandleOutboundConnected_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    connection->isConnected_ = true;
    connection->HandleOutboundConnected();
}

HWTEST_F(SoftbusConnectionTest, HandleInboundConnected_001, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();
    EXPECT_CALL(*coordinator, AddConnection(DEFAULT_TEST_CONNECTION_NAME, TEST_NETWORK_ID));
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

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    connection->HandleInboundConnected("test-connection");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(connection->IsConnected());
    EXPECT_EQ(connection->GetConnectionName(), DEFAULT_TEST_CONNECTION_NAME);
    EXPECT_TRUE(incomingCallbackInvoked);
}

HWTEST_F(SoftbusConnectionTest, HandleInboundConnected_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    connection->isConnected_ = true;
    connection->HandleInboundConnected("test-connection");
}

HWTEST_F(SoftbusConnectionTest, HandleInboundConnected_003, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, "existing-connection", key,
        TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    connection->HandleInboundConnected("new-connection");
    EXPECT_EQ(connection->GetConnectionName(), "existing-connection");
}

HWTEST_F(SoftbusConnectionTest, MarkShutdownByPeer_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    connection->MarkShutdownByPeer();

    EXPECT_TRUE(connection->isShutdownByPeer_);
}

HWTEST_F(SoftbusConnectionTest, Destructor_001, TestSize.Level0)
{
    MockGuard guard;
    auto coordinator = InstallCoordinatorMock();
    EXPECT_CALL(*coordinator, RemoveConnection(DEFAULT_TEST_CONNECTION_NAME));
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
        auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
            TEST_NETWORK_ID, manager_);
        ASSERT_NE(connection, nullptr);
    }

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SoftbusConnectionTest, Destructor_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    {
        auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager_);
        ASSERT_NE(connection, nullptr);
        connection->socketId_ = -1;
    }
}

HWTEST_F(SoftbusConnectionTest, Destructor_003, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    {
        auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
            TEST_NETWORK_ID, manager_);
        ASSERT_NE(connection, nullptr);
        connection->socketId_ = -1;
        connection->MarkShutdownByPeer();
    }
}

HWTEST_F(SoftbusConnectionTest, NotifyConnectionEstablished_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    connection->NotifyConnectionEstablished();
}

HWTEST_F(SoftbusConnectionTest, NotifyConnectionClosed_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    connection->NotifyConnectionClosed();
}

HWTEST_F(SoftbusConnectionTest, NotifyIncomingConnection_001, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);
    connection->isInbound_ = false;

    connection->NotifyIncomingConnection();
}

HWTEST_F(SoftbusConnectionTest, NotifyIncomingConnection_002, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    connection->NotifyIncomingConnection();
}

HWTEST_F(SoftbusConnectionTest, GetAcceptTimeMs_RecordsSteadyTime_OnInboundCtor, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    // Inbound (unnamed) ctor records the current steady time as accept time.
    guard.GetTimeKeeper().SetSteadyTime(5000);

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, key, TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    EXPECT_EQ(connection->GetAcceptTimeMs(), 5000);
}

HWTEST_F(SoftbusConnectionTest, GetAcceptTimeMs_DefaultZero_OnOutboundCtor, TestSize.Level0)
{
    MockGuard guard;
    InstallCoordinatorMock();
    ON_CALL(guard.GetMiscManager(), GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });

    // Outbound (named) ctor does not record an accept time (defaults to 0).
    guard.GetTimeKeeper().SetSteadyTime(7777);

    manager_ = SoftBusConnectionManager::Create();
    ASSERT_NE(manager_, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = TEST_DEVICE_ID;

    auto connection = std::make_shared<SoftbusConnection>(DEFAULT_TEST_SOCKET_ID, DEFAULT_TEST_CONNECTION_NAME, key,
        TEST_NETWORK_ID, manager_);
    ASSERT_NE(connection, nullptr);

    EXPECT_EQ(connection->GetAcceptTimeMs(), 0);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
