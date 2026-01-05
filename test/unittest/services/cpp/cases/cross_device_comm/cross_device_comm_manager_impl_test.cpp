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

#include "cross_device_comm_manager_impl.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_cross_device_channel.h"
#include "mock_misc_manager.h"
#include "mock_user_id_manager.h"

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
    void SetUp() override
    {
        const int32_t defaultUserId = 100;

        SingletonManager::GetInstance().Reset();

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto activeUserMgr = std::shared_ptr<IUserIdManager>(&mockActiveUserIdManager_, [](IUserIdManager *) {});
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
        ON_CALL(*mockChannel_, SubscribeAuthMaintainActive(_)).WillByDefault(Invoke([](OnAuthMaintainActiveChange &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel_, GetAuthMaintainActive()).WillByDefault(Return(false));
        ON_CALL(*mockChannel_, GetCompanionSecureProtocolId()).WillByDefault(Return(SecureProtocolId::DEFAULT));
        ON_CALL(*mockChannel_, SubscribeConnectionStatus(_)).WillByDefault(Invoke([](OnConnectionStatusChange &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel_, SubscribeIncomingConnection(_)).WillByDefault(Invoke([](OnIncomingConnection &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel_, SubscribeRawMessage(_)).WillByDefault(Invoke([](OnRawMessage &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel_, SubscribePhysicalDeviceStatus(_))
            .WillByDefault(Invoke([](OnPhysicalDeviceStatusChange &&) { return MakeSubscription(); }));
        ON_CALL(*mockChannel_, GetAllPhysicalDevices()).WillByDefault(Return(std::vector<PhysicalDeviceStatus> {}));
        ON_CALL(*mockChannel_, Start()).WillByDefault(Return(true));
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    int32_t nextGlobalId_ = 1;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockUserIdManager> mockActiveUserIdManager_;
    std::shared_ptr<NiceMock<MockCrossDeviceChannel>> mockChannel_;
};

HWTEST_F(CrossDeviceCommManagerImplTest, Create_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    EXPECT_NE(manager, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Create_002, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = {};
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Create_003, TestSize.Level0)
{
    EXPECT_CALL(*mockChannel_, SubscribeAuthMaintainActive(_)).WillOnce(Return(nullptr));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Create_004, TestSize.Level0)
{
    EXPECT_CALL(mockActiveUserIdManager_, SubscribeActiveUserId(_))
        .WillOnce(Invoke([](ActiveUserIdCallback &&) { return MakeSubscription(); }))
        .WillOnce(Return(nullptr));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Start_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    EXPECT_CALL(*mockChannel_, Start()).WillOnce(Return(true));

    bool result = manager->Start();
    EXPECT_TRUE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Start_002, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    EXPECT_CALL(*mockChannel_, Start()).WillOnce(Return(true));

    bool result1 = manager->Start();
    EXPECT_TRUE(result1);

    bool result2 = manager->Start();
    EXPECT_TRUE(result2);
}

HWTEST_F(CrossDeviceCommManagerImplTest, Start_003, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    EXPECT_CALL(*mockChannel_, Start()).WillOnce(Return(false));

    bool result = manager->Start();
    EXPECT_FALSE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeIsAuthMaintainActive_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeIsAuthMaintainActive([&callbackInvoked](bool) { callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetDeviceStatus_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    auto status = manager->GetDeviceStatus(deviceKey);
    EXPECT_FALSE(status.has_value());
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetAllDeviceStatus_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    auto allStatus = manager->GetAllDeviceStatus();
    EXPECT_TRUE(allStatus.empty());
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeAllDeviceStatus_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeAllDeviceStatus(
        [&callbackInvoked](const std::vector<DeviceStatus> &) { callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, SetSubscribeMode_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    manager->SetSubscribeMode(SUBSCRIBE_MODE_MANAGE);
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetManageSubscribeTime_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    auto time = manager->GetManageSubscribeTime();
    EXPECT_FALSE(time.has_value());
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeDeviceStatus_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeDeviceStatus(deviceKey,
        [&callbackInvoked](const std::vector<DeviceStatus> &) { callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, OpenConnection_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "remote-device";
    deviceKey.deviceUserId = 100;

    std::string connectionName;
    bool result = manager->OpenConnection(deviceKey, connectionName);
    EXPECT_FALSE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, CloseConnection_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    manager->CloseConnection("test-connection");
}

HWTEST_F(CrossDeviceCommManagerImplTest, IsConnectionOpen_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    bool result = manager->IsConnectionOpen("test-connection");
    EXPECT_FALSE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetConnectionStatus_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    auto status = manager->GetConnectionStatus("test-connection");
    EXPECT_EQ(status, ConnectionStatus::DISCONNECTED);
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetLocalDeviceKeyByConnectionName_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    auto deviceKey = manager->GetLocalDeviceKeyByConnectionName("test-connection");
    EXPECT_FALSE(deviceKey.has_value());
}

HWTEST_F(CrossDeviceCommManagerImplTest, GetLocalDeviceKeyByConnectionName_002, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    auto deviceKey = manager->GetLocalDeviceKeyByConnectionName("");
    EXPECT_FALSE(deviceKey.has_value());
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeConnectionStatus_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeConnectionStatus("test-connection",
        [&callbackInvoked](const std::string &, ConnectionStatus, const std::string &) { callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeIncomingConnection_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeIncomingConnection(MessageType::TOKEN_AUTH,
        [&callbackInvoked](const Attributes &, OnMessageReply &) { callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, SendMessage_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    Attributes request;
    bool result = manager->SendMessage("test-connection", MessageType::KEEP_ALIVE, request, nullptr);
    EXPECT_FALSE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, SubscribeMessage_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeMessage("test-connection", MessageType::TOKEN_AUTH,
        [&callbackInvoked](const Attributes &, OnMessageReply &) { callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(CrossDeviceCommManagerImplTest, CheckOperationIntent_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
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
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "test-device";
    deviceKey.deviceUserId = 100;

    bool callbackInvoked = false;
    bool result = manager->CheckOperationIntent(deviceKey, 123, [&callbackInvoked](bool) { callbackInvoked = true; });
    EXPECT_FALSE(result);
}

HWTEST_F(CrossDeviceCommManagerImplTest, HostGetSecureProtocolId_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    DeviceKey companionDeviceKey;
    companionDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    companionDeviceKey.deviceId = "companion-device";
    companionDeviceKey.deviceUserId = 100;

    auto protocolId = manager->HostGetSecureProtocolId(companionDeviceKey);
    EXPECT_FALSE(protocolId.has_value());
}

HWTEST_F(CrossDeviceCommManagerImplTest, CompanionGetSecureProtocolId_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto manager = CrossDeviceCommManagerImpl::Create(channels);
    ASSERT_NE(manager, nullptr);

    auto protocolId = manager->CompanionGetSecureProtocolId();
    EXPECT_NE(protocolId, SecureProtocolId::INVALID);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
