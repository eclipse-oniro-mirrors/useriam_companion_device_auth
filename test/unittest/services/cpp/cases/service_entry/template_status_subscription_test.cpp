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

#include "mock_guard.h"
#include "subscription.h"
#include "subscription_manager.h"
#include "template_status_subscription.h"

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

class MockIIpcTemplateStatusCallback : public IIpcTemplateStatusCallback {
public:
    MockIIpcTemplateStatusCallback() = default;
    ~MockIIpcTemplateStatusCallback() override = default;

    MOCK_METHOD(int32_t, OnTemplateStatusChange, (const std::vector<IpcTemplateStatus> &templateStatusList),
        (override));
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
};

class TemplateStatusSubscriptionTest : public Test {};

HWTEST_F(TemplateStatusSubscriptionTest, Create_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([](OnCompanionDeviceStatusChange &&callback) { return MakeSubscription(); }));
    EXPECT_CALL(guard.GetCompanionManager(), GetAllCompanionStatus()).WillOnce(Return(std::vector<CompanionStatus> {}));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetManageSubscribeTime()).WillOnce(Return(std::nullopt));

    auto subscription = TemplateStatusSubscription::Create(userId, subscriptionManager);

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(TemplateStatusSubscriptionTest, Create_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_)).WillOnce(Return(nullptr));

    auto subscription = TemplateStatusSubscription::Create(userId, subscriptionManager);

    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(TemplateStatusSubscriptionTest, GetUserId_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;

    auto subscription = TemplateStatusSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    EXPECT_EQ(subscription->GetUserId(), userId);
}

HWTEST_F(TemplateStatusSubscriptionTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;

    auto subscription = TemplateStatusSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    auto weakPtr = subscription->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(TemplateStatusSubscriptionTest, OnCallbackAdded_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;

    auto subscription = TemplateStatusSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscription->OnCallbackAdded(callback);
}

HWTEST_F(TemplateStatusSubscriptionTest, OnCallbackAdded_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    UserId userId = 100;

    auto subscription = TemplateStatusSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    sptr<MockIIpcTemplateStatusCallback> callback = nullptr;

    subscription->OnCallbackAdded(callback);
}

HWTEST_F(TemplateStatusSubscriptionTest, HandleCompanionStatusChange_001, TestSize.Level0)
{
    MockGuard guard;
    UserId userId = 100;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    OnCompanionDeviceStatusChange storedCallback;

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&storedCallback](OnCompanionDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));

    auto subscription = TemplateStatusSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    std::vector<CompanionStatus> companionStatusList = {};

    if (storedCallback) {
        storedCallback(companionStatusList);
    }

    EXPECT_TRUE(subscription->cachedTemplateStatus_.empty());
}

HWTEST_F(TemplateStatusSubscriptionTest, HandleCompanionStatusChange_002, TestSize.Level0)
{
    MockGuard guard;
    UserId userId = 100;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    OnCompanionDeviceStatusChange storedCallback;

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&storedCallback](OnCompanionDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));

    auto subscription = TemplateStatusSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    CompanionStatus status {};
    status.hostUserId = userId;

    std::vector<CompanionStatus> companionStatusList = { status };

    if (storedCallback) {
        storedCallback(companionStatusList);
    }

    EXPECT_FALSE(subscription->cachedTemplateStatus_.empty());
}

HWTEST_F(TemplateStatusSubscriptionTest, HandleCompanionStatusChange_003, TestSize.Level0)
{
    MockGuard guard;
    UserId userId = 100;
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    OnCompanionDeviceStatusChange storedCallback;

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&storedCallback](OnCompanionDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));

    auto subscription = TemplateStatusSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    CompanionStatus status {};
    status.hostUserId = 200;

    std::vector<CompanionStatus> companionStatusList = { status };

    if (storedCallback) {
        storedCallback(companionStatusList);
    }

    EXPECT_TRUE(subscription->cachedTemplateStatus_.empty());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
