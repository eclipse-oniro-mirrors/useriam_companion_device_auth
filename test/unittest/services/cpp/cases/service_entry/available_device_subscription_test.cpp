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
#include "mock_guard.h"
#include "subscription.h"
#include "subscription_manager.h"

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

class AvailableDeviceSubscriptionTest : public Test {};

HWTEST_F(AvailableDeviceSubscriptionTest, Create_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([](OnDeviceStatusChange &&callback) { return MakeSubscription(); }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetAllDeviceStatus()).WillOnce(Return(std::vector<DeviceStatus> {}));
    EXPECT_CALL(guard.GetUserIdManager(), GetActiveUserId()).WillOnce(Return(0));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(AvailableDeviceSubscriptionTest, Create_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_)).WillOnce(Return(nullptr));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);

    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(AvailableDeviceSubscriptionTest, GetUserId_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    EXPECT_EQ(subscription->GetUserId(), userId);
}

HWTEST_F(AvailableDeviceSubscriptionTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    auto weakPtr = subscription->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(AvailableDeviceSubscriptionTest, OnCallbackAdded_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscription->OnCallbackAdded(callback);
}

HWTEST_F(AvailableDeviceSubscriptionTest, OnCallbackAdded_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    sptr<MockIIpcAvailableDeviceStatusCallback> callback = nullptr;

    subscription->OnCallbackAdded(callback);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
