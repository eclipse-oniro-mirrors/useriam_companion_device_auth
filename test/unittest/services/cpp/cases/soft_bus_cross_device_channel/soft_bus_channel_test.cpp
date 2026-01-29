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
#include "soft_bus_channel.h"
#include "task_runner_manager.h"

#include "adapter_manager.h"
#include "mock_misc_manager.h"
#include "mock_system_param_manager.h"
#include "mock_time_keeper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr uint64_t UINT64_1 = 1;

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class SoftBusChannelTest : public testing::Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto systemParamMgr =
            std::shared_ptr<ISystemParamManager>(&mockSystemParamManager_, [](ISystemParamManager *) {});
        AdapterManager::GetInstance().SetSystemParamManager(systemParamMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        ON_CALL(mockMiscManager_, GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });
        ON_CALL(mockMiscManager_, GetLocalUdid()).WillByDefault(Return(std::optional<std::string>("test-local-udid")));
        ON_CALL(mockSystemParamManager_, WatchParam(_, _)).WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockSystemParamManager_, GetParam(_, _)).WillByDefault(Return(std::string(FALSE_STR)));
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

protected:
    uint64_t nextGlobalId_ = UINT64_1;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockSystemParamManager> mockSystemParamManager_;
};

HWTEST_F(SoftBusChannelTest, Create_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    EXPECT_NE(channel, nullptr);
}

HWTEST_F(SoftBusChannelTest, GetChannelId_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    auto channelId = channel->GetChannelId();
    EXPECT_EQ(channelId, ChannelId::SOFTBUS);
}

HWTEST_F(SoftBusChannelTest, GetLocalPhysicalDeviceKey_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    auto key = channel->GetLocalPhysicalDeviceKey();
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(key.value().idType, DeviceIdType::UNIFIED_DEVICE_ID);
    EXPECT_EQ(key.value().deviceId, "test-local-udid");
}

HWTEST_F(SoftBusChannelTest, GetLocalPhysicalDeviceKey_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->deviceStatusManager_ = nullptr;
    auto key = channel->GetLocalPhysicalDeviceKey();

    EXPECT_FALSE(key.has_value());
}

HWTEST_F(SoftBusChannelTest, GetCompanionSecureProtocolId_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    auto protocolId = channel->GetCompanionSecureProtocolId();
    EXPECT_EQ(protocolId, SecureProtocolId::DEFAULT);
}

HWTEST_F(SoftBusChannelTest, Start_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    bool result = channel->Start();
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusChannelTest, Start_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->started_ = true;

    bool result = channel->Start();
    EXPECT_TRUE(result);
}

HWTEST_F(SoftBusChannelTest, Start_003, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->connectionManager_ = nullptr;

    bool result = channel->Start();
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusChannelTest, Start_004, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->deviceStatusManager_ = nullptr;

    bool result = channel->Start();
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusChannelTest, SubscribePhysicalDeviceStatus_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    bool callbackInvoked = false;
    auto subscription = channel->SubscribePhysicalDeviceStatus(
        [&callbackInvoked](const std::vector<PhysicalDeviceStatus> &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusChannelTest, SubscribePhysicalDeviceStatus_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->deviceStatusManager_ = nullptr;

    bool callbackInvoked = false;
    auto subscription = channel->SubscribePhysicalDeviceStatus(
        [&callbackInvoked](const std::vector<PhysicalDeviceStatus> &) { callbackInvoked = true; });

    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusChannelTest, SubscribeRawMessage_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    bool callbackInvoked = false;
    auto subscription = channel->SubscribeRawMessage(
        [&callbackInvoked](const std::string &, const std::vector<uint8_t> &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusChannelTest, SubscribeRawMessage_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->connectionManager_ = nullptr;

    bool callbackInvoked = false;
    auto subscription = channel->SubscribeRawMessage(
        [&callbackInvoked](const std::string &, const std::vector<uint8_t> &) { callbackInvoked = true; });

    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusChannelTest, SubscribeConnectionStatus_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    bool callbackInvoked = false;
    auto subscription = channel->SubscribeConnectionStatus(
        [&callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusChannelTest, SubscribeConnectionStatus_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->connectionManager_ = nullptr;

    bool callbackInvoked = false;
    auto subscription = channel->SubscribeConnectionStatus(
        [&callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { callbackInvoked = true; });

    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusChannelTest, SubscribeIncomingConnection_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    bool callbackInvoked = false;
    auto subscription = channel->SubscribeIncomingConnection(
        [&callbackInvoked](const std::string &, const PhysicalDeviceKey &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusChannelTest, SubscribeIncomingConnection_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->connectionManager_ = nullptr;

    bool callbackInvoked = false;
    auto subscription = channel->SubscribeIncomingConnection(
        [&callbackInvoked](const std::string &, const PhysicalDeviceKey &) { callbackInvoked = true; });

    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusChannelTest, SubscribeAuthMaintainActive_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    bool callbackInvoked = false;
    auto subscription = channel->SubscribeAuthMaintainActive([&callbackInvoked](bool) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusChannelTest, SubscribeAuthMaintainActive_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->deviceStatusManager_ = nullptr;

    bool callbackInvoked = false;
    auto subscription = channel->SubscribeAuthMaintainActive([&callbackInvoked](bool) { callbackInvoked = true; });

    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusChannelTest, GetAuthMaintainActive_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    bool isActive = channel->GetAuthMaintainActive();
    EXPECT_FALSE(isActive);
}

HWTEST_F(SoftBusChannelTest, GetAuthMaintainActive_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->deviceStatusManager_ = nullptr;

    bool isActive = channel->GetAuthMaintainActive();
    EXPECT_FALSE(isActive);
}

HWTEST_F(SoftBusChannelTest, GetAllPhysicalDevices_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    auto devices = channel->GetAllPhysicalDevices();
    EXPECT_TRUE(devices.empty());
}

HWTEST_F(SoftBusChannelTest, GetAllPhysicalDevices_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->deviceStatusManager_ = nullptr;

    auto devices = channel->GetAllPhysicalDevices();
    EXPECT_TRUE(devices.empty());
}

HWTEST_F(SoftBusChannelTest, SendMessage_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    std::vector<uint8_t> message = { 1, 2, 3, 4 };
    bool result = channel->SendMessage("test-connection", message);
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusChannelTest, SendMessage_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->connectionManager_ = nullptr;

    std::vector<uint8_t> message = { 1, 2, 3, 4 };
    bool result = channel->SendMessage("test-connection", message);
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusChannelTest, OpenConnection_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device-id";

    bool result = channel->OpenConnection("test-connection", key);

    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusChannelTest, OpenConnection_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);
    channel->connectionManager_ = nullptr;

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device-id";

    bool result = channel->OpenConnection("test-connection", key);

    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusChannelTest, OpenConnection_003, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);
    channel->deviceStatusManager_ = nullptr;

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device-id";

    bool result = channel->OpenConnection("test-connection", key);

    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusChannelTest, OpenConnection_004, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device-id";

    PhysicalDeviceStatus status;
    status.physicalDeviceKey = key;
    channel->deviceStatusManager_->physicalDeviceStatus_.push_back(status);

    bool result = channel->OpenConnection("test-connection", key);

    EXPECT_TRUE(result);
}

HWTEST_F(SoftBusChannelTest, CloseConnection_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->CloseConnection("test-connection");
}

HWTEST_F(SoftBusChannelTest, CloseConnection_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->connectionManager_ = nullptr;

    channel->CloseConnection("test-connection");
}

HWTEST_F(SoftBusChannelTest, CheckOperationIntent_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    bool result = channel->CheckOperationIntent(deviceKey, 12345, nullptr);
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusChannelTest, CheckOperationIntent_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    EXPECT_CALL(mockMiscManager_, GetDeviceDeviceSelectResult(_, _, _)).WillOnce(Return(false));

    bool resultInvoked = false;
    bool result =
        channel->CheckOperationIntent(deviceKey, 12345, [&resultInvoked](bool confirmed) { resultInvoked = true; });

    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusChannelTest, CheckOperationIntent_003, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    EXPECT_CALL(mockMiscManager_, GetDeviceDeviceSelectResult(_, _, _))
        .WillOnce(
            Invoke([&deviceKey](uint32_t, SelectPurpose, std::function<void(const std::vector<DeviceKey> &)> callback) {
                std::vector<DeviceKey> selected = { deviceKey };
                callback(selected);
                return true;
            }));

    bool confirmed = false;
    bool resultInvoked = false;
    bool result = channel->CheckOperationIntent(deviceKey, 12345, [&resultInvoked, &confirmed](bool confirm) {
        resultInvoked = true;
        confirmed = confirm;
    });

    EXPECT_TRUE(result);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(resultInvoked);
    EXPECT_TRUE(confirmed);
}

HWTEST_F(SoftBusChannelTest, CheckOperationIntent_004, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    EXPECT_CALL(mockMiscManager_, GetDeviceDeviceSelectResult(_, _, _))
        .WillOnce(Invoke([](uint32_t, SelectPurpose, std::function<void(const std::vector<DeviceKey> &)> callback) {
            std::vector<DeviceKey> selected;
            callback(selected);
            return true;
        }));

    bool confirmed = true;
    bool resultInvoked = false;
    bool result = channel->CheckOperationIntent(deviceKey, 12345, [&resultInvoked, &confirmed](bool confirm) {
        resultInvoked = true;
        confirmed = confirm;
    });

    EXPECT_TRUE(result);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(resultInvoked);
    EXPECT_FALSE(confirmed);
}

HWTEST_F(SoftBusChannelTest, CheckOperationIntent_005, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    DeviceKey otherDevice;
    otherDevice.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    otherDevice.deviceId = "other-device";
    otherDevice.deviceUserId = 200;

    EXPECT_CALL(mockMiscManager_, GetDeviceDeviceSelectResult(_, _, _))
        .WillOnce(Invoke(
            [&otherDevice](uint32_t, SelectPurpose, std::function<void(const std::vector<DeviceKey> &)> callback) {
                std::vector<DeviceKey> selected = { otherDevice };
                callback(selected);
                return true;
            }));

    bool confirmed = true;
    bool resultInvoked = false;
    bool result = channel->CheckOperationIntent(deviceKey, 12345, [&resultInvoked, &confirmed](bool confirm) {
        resultInvoked = true;
        confirmed = confirm;
    });

    EXPECT_TRUE(result);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(resultInvoked);
    EXPECT_FALSE(confirmed);
}

HWTEST_F(SoftBusChannelTest, OnRemoteDisconnect_001, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->OnRemoteDisconnect("test-connection", "test-reason");
}

HWTEST_F(SoftBusChannelTest, OnRemoteDisconnect_002, TestSize.Level0)
{
    auto channel = SoftBusChannel::Create();
    ASSERT_NE(channel, nullptr);

    channel->connectionManager_ = nullptr;

    channel->OnRemoteDisconnect("test-connection", "test-reason");
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
