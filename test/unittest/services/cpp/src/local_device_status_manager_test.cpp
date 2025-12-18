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
#include "local_device_status_manager.h"
#include "mock_active_user_id_manager.h"
#include "mock_cross_device_channel.h"
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

class LocalDeviceStatusManagerTest : public Test {
public:
    void SetUp() override
    {
        const int32_t defaultUserId = 100;

        SingletonManager::GetInstance().Reset();

        mockChannel_ = std::make_shared<NiceMock<MockCrossDeviceChannel>>();

        PhysicalDeviceKey localPhysicalKey;
        localPhysicalKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        localPhysicalKey.deviceId = "local-device-id";

        ON_CALL(*mockChannel_, GetChannelId).WillByDefault(Return(ChannelId::SOFTBUS));
        ON_CALL(*mockChannel_, GetLocalPhysicalDeviceKey).WillByDefault(Return(localPhysicalKey));
        ON_CALL(*mockChannel_, SubscribeAuthMaintainActive(_))
            .WillByDefault(Invoke([this](OnAuthMaintainActiveChange &&callback) {
                authMaintainCallback_ = std::move(callback);
                return MakeSubscription();
            }));
        ON_CALL(*mockChannel_, GetAuthMaintainActive).WillByDefault(Return(false));
        ON_CALL(*mockChannel_, GetcompanionSecureProtocolId).WillByDefault(Return(SecureProtocolId::DEFAULT));

        auto activeUserMgr =
            std::shared_ptr<IActiveUserIdManager>(&mockActiveUserIdManager_, [](IActiveUserIdManager *) {});
        SingletonManager::GetInstance().SetActiveUserIdManager(activeUserMgr);

        ON_CALL(mockActiveUserIdManager_, SubscribeActiveUserId(_))
            .WillByDefault(Invoke([this](ActiveUserIdCallback &&callback) {
                activeUserIdCallback_ = std::move(callback);
                return MakeSubscription();
            }));
        ON_CALL(mockActiveUserIdManager_, GetActiveUserId).WillByDefault(Return(defaultUserId));
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    std::shared_ptr<NiceMock<MockCrossDeviceChannel>> mockChannel_;
    NiceMock<MockActiveUserIdManager> mockActiveUserIdManager_;
    OnAuthMaintainActiveChange authMaintainCallback_;
    ActiveUserIdCallback activeUserIdCallback_;
};

HWTEST_F(LocalDeviceStatusManagerTest, Create_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    EXPECT_NE(manager, nullptr);
}

HWTEST_F(LocalDeviceStatusManagerTest, Create_002, TestSize.Level0)
{
    auto manager = LocalDeviceStatusManager::Create(nullptr);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(LocalDeviceStatusManagerTest, Create_003, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = {};
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(LocalDeviceStatusManagerTest, Create_004, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    EXPECT_CALL(*mockChannel_, SubscribeAuthMaintainActive(_)).WillOnce(Return(nullptr));

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(LocalDeviceStatusManagerTest, Create_005, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    EXPECT_CALL(mockActiveUserIdManager_, SubscribeActiveUserId(_)).WillOnce(Return(nullptr));

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    EXPECT_EQ(manager, nullptr);
}

HWTEST_F(LocalDeviceStatusManagerTest, GetLocalDeviceStatus_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    auto status = manager->GetLocalDeviceStatus();
    EXPECT_FALSE(status.protocols.empty());
    EXPECT_FALSE(status.capabilities.empty());
    EXPECT_EQ(status.isAuthMaintainActive, false);
}

HWTEST_F(LocalDeviceStatusManagerTest, SubscribeLocalDeviceStatus_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription =
        manager->SubscribeLocalDeviceStatus([&callbackInvoked](const LocalDeviceStatus &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);

    manager->SetAuthMaintainActive(true);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
    EXPECT_TRUE(manager->isAuthMaintainActive());
}

HWTEST_F(LocalDeviceStatusManagerTest, SubscribeLocalDeviceStatus_002, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    {
        auto subscription = manager->SubscribeLocalDeviceStatus(
            [&callbackInvoked](const LocalDeviceStatus &) { callbackInvoked = true; });
        EXPECT_NE(subscription, nullptr);
    }

    manager->SetAuthMaintainActive(true);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackInvoked);
    EXPECT_TRUE(manager->isAuthMaintainActive());
}

HWTEST_F(LocalDeviceStatusManagerTest, OnActiveUserIdChanged_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeLocalDeviceStatus([&callbackInvoked](const LocalDeviceStatus &status) {
        callbackInvoked = true;
        EXPECT_EQ(status.channelId2DeviceKey.begin()->second.deviceUserId, 200);
    });

    ASSERT_TRUE(activeUserIdCallback_ != nullptr);
    activeUserIdCallback_(200);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(LocalDeviceStatusManagerTest, OnActiveUserIdChanged_002, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription =
        manager->SubscribeLocalDeviceStatus([&callbackInvoked](const LocalDeviceStatus &) { callbackInvoked = true; });

    ASSERT_TRUE(activeUserIdCallback_ != nullptr);
    activeUserIdCallback_(100);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackInvoked);
}

HWTEST_F(LocalDeviceStatusManagerTest, AuthMaintainCallback_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeLocalDeviceStatus([&callbackInvoked](const LocalDeviceStatus &status) {
        callbackInvoked = true;
        EXPECT_TRUE(status.isAuthMaintainActive);
    });

    ASSERT_TRUE(authMaintainCallback_ != nullptr);
    authMaintainCallback_(true);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
    EXPECT_TRUE(manager->isAuthMaintainActive());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
