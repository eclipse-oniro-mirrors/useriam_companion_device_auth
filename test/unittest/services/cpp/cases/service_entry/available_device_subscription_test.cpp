/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "available_device_subscription.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "subscription.h"
#include "subscription_manager.h"
#include "task_runner_manager.h"

#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_remote_object.h"
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

class MockIIpcAvailableDeviceStatusCallback : public IIpcAvailableDeviceStatusCallback {
public:
    MockIIpcAvailableDeviceStatusCallback() = default;
    ~MockIIpcAvailableDeviceStatusCallback() override = default;

    MOCK_METHOD(ErrCode, OnAvailableDeviceStatusChange, (const std::vector<IpcDeviceStatus> &deviceStatusList),
        (override));
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
};

class AvailableDeviceSubscriptionTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto activeUserMgr = std::shared_ptr<IUserIdManager>(&mockActiveUserIdManager_, [](IUserIdManager *) {});
        SingletonManager::GetInstance().SetActiveUserIdManager(activeUserMgr);

        auto companionMgr = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionMgr);

        ON_CALL(mockCrossDeviceCommManager_, SubscribeAllDeviceStatus(_))
            .WillByDefault(Invoke([](OnDeviceStatusChange &&callback) { return MakeSubscription(); }));
        ON_CALL(mockCrossDeviceCommManager_, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
        ON_CALL(mockActiveUserIdManager_, GetActiveUserId()).WillByDefault(Return(0));

        subscriptionManager_ = std::make_shared<SubscriptionManager>();
    }

    void TearDown() override
    {
        subscriptionManager_.reset();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockUserIdManager> mockActiveUserIdManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    std::shared_ptr<SubscriptionManager> subscriptionManager_;
};

HWTEST_F(AvailableDeviceSubscriptionTest, Create_001, TestSize.Level0)
{
    UserId userId = 100;

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([](OnDeviceStatusChange &&callback) { return MakeSubscription(); }));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetAllDeviceStatus()).WillOnce(Return(std::vector<DeviceStatus> {}));
    EXPECT_CALL(mockActiveUserIdManager_, GetActiveUserId()).WillOnce(Return(0));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager_);

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(AvailableDeviceSubscriptionTest, Create_002, TestSize.Level0)
{
    UserId userId = 100;

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeAllDeviceStatus(_)).WillOnce(Return(nullptr));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager_);

    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(AvailableDeviceSubscriptionTest, GetUserId_001, TestSize.Level0)
{
    UserId userId = 100;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    EXPECT_EQ(subscription->GetUserId(), userId);
}

HWTEST_F(AvailableDeviceSubscriptionTest, GetWeakPtr_001, TestSize.Level0)
{
    UserId userId = 100;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    auto weakPtr = subscription->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(AvailableDeviceSubscriptionTest, OnCallbackAdded_001, TestSize.Level0)
{
    UserId userId = 100;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscription->OnCallbackAdded(callback);
}

HWTEST_F(AvailableDeviceSubscriptionTest, OnCallbackAdded_002, TestSize.Level0)
{
    UserId userId = 100;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    sptr<MockIIpcAvailableDeviceStatusCallback> callback = nullptr;

    subscription->OnCallbackAdded(callback);
}

HWTEST_F(AvailableDeviceSubscriptionTest, HandleDeviceStatusChange_001, TestSize.Level0)
{
    UserId userId = 100;
    OnDeviceStatusChange storedCallback;

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([&storedCallback](OnDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetAllDeviceStatus()).WillOnce(Return(std::vector<DeviceStatus> {}));
    EXPECT_CALL(mockActiveUserIdManager_, GetActiveUserId()).WillOnce(Return(0)).WillOnce(Return(userId));
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::nullopt));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    DeviceKey deviceKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "test_device_id",
        .deviceUserId = 200 };
    DeviceStatus deviceStatus = { .deviceKey = deviceKey,
        .channelId = ChannelId::SOFTBUS,
        .deviceModelInfo = "test_model",
        .deviceUserName = "test_user",
        .deviceName = "test_device" };
    std::vector<DeviceStatus> deviceStatusList = { deviceStatus };

    if (storedCallback) {
        storedCallback(deviceStatusList);
    }

    EXPECT_FALSE(subscription->cachedAvailableDeviceStatus_.empty());
}

HWTEST_F(AvailableDeviceSubscriptionTest, HandleDeviceStatusChange_002, TestSize.Level0)
{
    UserId userId = 100;
    OnDeviceStatusChange storedCallback;

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([&storedCallback](OnDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetAllDeviceStatus()).WillOnce(Return(std::vector<DeviceStatus> {}));
    EXPECT_CALL(mockActiveUserIdManager_, GetActiveUserId()).WillOnce(Return(0)).WillOnce(Return(userId));

    CompanionStatus companionStatus {};
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(companionStatus));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    DeviceKey deviceKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "test_device_id",
        .deviceUserId = 200 };
    DeviceStatus deviceStatus = { .deviceKey = deviceKey,
        .channelId = ChannelId::SOFTBUS,
        .deviceModelInfo = "test_model",
        .deviceUserName = "test_user",
        .deviceName = "test_device" };
    std::vector<DeviceStatus> deviceStatusList = { deviceStatus };

    if (storedCallback) {
        storedCallback(deviceStatusList);
    }

    EXPECT_TRUE(subscription->cachedAvailableDeviceStatus_.empty());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
