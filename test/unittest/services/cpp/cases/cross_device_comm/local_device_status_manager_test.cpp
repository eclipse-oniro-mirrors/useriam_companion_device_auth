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
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_cross_device_channel.h"
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
        ON_CALL(*mockChannel_, GetCompanionSecureProtocolId).WillByDefault(Return(SecureProtocolId::DEFAULT));

        auto activeUserMgr = std::shared_ptr<IUserIdManager>(&mockActiveUserIdManager_, [](IUserIdManager *) {});
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
    NiceMock<MockUserIdManager> mockActiveUserIdManager_;
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

HWTEST_F(LocalDeviceStatusManagerTest, SubscribeIsAuthMaintainActive_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeIsAuthMaintainActive([&callbackInvoked](bool) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);

    manager->SetAuthMaintainActive(true);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
    EXPECT_TRUE(manager->IsAuthMaintainActive());
}

HWTEST_F(LocalDeviceStatusManagerTest, SubscribeIsAuthMaintainActive_002, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    {
        auto subscription =
            manager->SubscribeIsAuthMaintainActive([&callbackInvoked](bool) { callbackInvoked = true; });
        EXPECT_NE(subscription, nullptr);
    }

    manager->SetAuthMaintainActive(true);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackInvoked);
    EXPECT_TRUE(manager->IsAuthMaintainActive());
}

HWTEST_F(LocalDeviceStatusManagerTest, OnActiveUserIdChanged_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    ASSERT_TRUE(activeUserIdCallback_ != nullptr);
    activeUserIdCallback_(200);
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(LocalDeviceStatusManagerTest, OnActiveUserIdChanged_002, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeIsAuthMaintainActive([&callbackInvoked](bool) { callbackInvoked = true; });

    ASSERT_TRUE(activeUserIdCallback_ != nullptr);
    activeUserIdCallback_(100);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(LocalDeviceStatusManagerTest, AuthMaintainCallback_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeIsAuthMaintainActive([&callbackInvoked](bool isActive) {
        callbackInvoked = true;
        EXPECT_TRUE(isActive);
    });

    ASSERT_TRUE(authMaintainCallback_ != nullptr);
    authMaintainCallback_(true);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
    EXPECT_TRUE(manager->IsAuthMaintainActive());
}

HWTEST_F(LocalDeviceStatusManagerTest, GetLocalDeviceKey_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    auto deviceKeyOpt = manager->GetLocalDeviceKey(ChannelId::SOFTBUS);
    ASSERT_TRUE(deviceKeyOpt.has_value());

    const auto &deviceKey = deviceKeyOpt.value();
    EXPECT_EQ(deviceKey.idType, DeviceIdType::UNIFIED_DEVICE_ID);
    EXPECT_EQ(deviceKey.deviceId, "local-device-id");
    EXPECT_EQ(deviceKey.deviceUserId, 100);
}

HWTEST_F(LocalDeviceStatusManagerTest, GetLocalDeviceKey_002, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    auto deviceKeyOpt = manager->GetLocalDeviceKey(ChannelId::INVALID);
    EXPECT_FALSE(deviceKeyOpt.has_value());
}

HWTEST_F(LocalDeviceStatusManagerTest, GetLocalDeviceKey_003, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    EXPECT_CALL(*mockChannel_, GetLocalPhysicalDeviceKey).WillOnce(Return(std::nullopt));

    auto deviceKeyOpt = manager->GetLocalDeviceKey(ChannelId::SOFTBUS);
    EXPECT_FALSE(deviceKeyOpt.has_value());
}

HWTEST_F(LocalDeviceStatusManagerTest, GetLocalDeviceKeys_001, TestSize.Level0)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_ };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    auto deviceKeys = manager->GetLocalDeviceKeys();
    EXPECT_EQ(deviceKeys.size(), 1);

    auto it = deviceKeys.find(ChannelId::SOFTBUS);
    ASSERT_NE(it, deviceKeys.end());

    const auto &deviceKey = it->second;
    EXPECT_EQ(deviceKey.idType, DeviceIdType::UNIFIED_DEVICE_ID);
    EXPECT_EQ(deviceKey.deviceId, "local-device-id");
    EXPECT_EQ(deviceKey.deviceUserId, 100);
}

HWTEST_F(LocalDeviceStatusManagerTest, GetLocalDeviceKeys_002, TestSize.Level0)
{
    auto mockChannel2 = std::make_shared<NiceMock<MockCrossDeviceChannel>>();

    PhysicalDeviceKey localPhysicalKey2;
    localPhysicalKey2.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    localPhysicalKey2.deviceId = "local-device-id-2";

    ON_CALL(*mockChannel2, GetChannelId).WillByDefault(Return(ChannelId::SOFTBUS));
    ON_CALL(*mockChannel2, GetLocalPhysicalDeviceKey).WillByDefault(Return(localPhysicalKey2));
    ON_CALL(*mockChannel2, SubscribeAuthMaintainActive(_)).WillByDefault(Invoke([](OnAuthMaintainActiveChange &&) {
        return MakeSubscription();
    }));
    ON_CALL(*mockChannel2, GetAuthMaintainActive).WillByDefault(Return(false));
    ON_CALL(*mockChannel2, GetCompanionSecureProtocolId).WillByDefault(Return(SecureProtocolId::DEFAULT));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_, nullptr, mockChannel2 };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    auto deviceKeys = manager->GetLocalDeviceKeys();
    EXPECT_EQ(deviceKeys.size(), 1);

    auto it1 = deviceKeys.find(ChannelId::SOFTBUS);
    ASSERT_NE(it1, deviceKeys.end());
    EXPECT_EQ(it1->second.deviceId, "local-device-id");
}

HWTEST_F(LocalDeviceStatusManagerTest, GetLocalDeviceKeys_003, TestSize.Level0)
{
    auto mockChannel2 = std::make_shared<NiceMock<MockCrossDeviceChannel>>();

    ON_CALL(*mockChannel2, GetChannelId).WillByDefault(Return(ChannelId::SOFTBUS));
    ON_CALL(*mockChannel2, GetLocalPhysicalDeviceKey).WillByDefault(Return(std::nullopt));
    ON_CALL(*mockChannel2, SubscribeAuthMaintainActive(_)).WillByDefault(Invoke([](OnAuthMaintainActiveChange &&) {
        return MakeSubscription();
    }));
    ON_CALL(*mockChannel2, GetAuthMaintainActive).WillByDefault(Return(false));
    ON_CALL(*mockChannel2, GetCompanionSecureProtocolId).WillByDefault(Return(SecureProtocolId::DEFAULT));

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels = { mockChannel_, mockChannel2 };
    auto channelMgr = std::make_shared<ChannelManager>(channels);

    auto manager = LocalDeviceStatusManager::Create(channelMgr);
    ASSERT_NE(manager, nullptr);

    auto deviceKeys = manager->GetLocalDeviceKeys();
    EXPECT_EQ(deviceKeys.size(), 1);

    auto it = deviceKeys.find(ChannelId::SOFTBUS);
    ASSERT_NE(it, deviceKeys.end());
    EXPECT_EQ(it->second.deviceId, "local-device-id");
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
