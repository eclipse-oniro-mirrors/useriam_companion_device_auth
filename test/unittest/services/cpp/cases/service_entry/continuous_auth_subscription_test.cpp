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

#include "continuous_auth_subscription.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "subscription.h"
#include "subscription_manager.h"
#include "task_runner_manager.h"

#include "mock_companion_manager.h"
#include "mock_remote_object.h"

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

class MockIIpcContinuousAuthStatusCallback : public IIpcContinuousAuthStatusCallback {
public:
    MockIIpcContinuousAuthStatusCallback() = default;
    ~MockIIpcContinuousAuthStatusCallback() override = default;

    MOCK_METHOD(int32_t, OnContinuousAuthStatusChange, (const IpcContinuousAuthStatus &status), (override));
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
};

class ContinuousAuthSubscriptionTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto companionMgr = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionMgr);

        ON_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
            .WillByDefault(Invoke([](OnCompanionDeviceStatusChange &&callback) { return MakeSubscription(); }));
        ON_CALL(mockCompanionManager_, GetAllCompanionStatus()).WillByDefault(Return(std::vector<CompanionStatus> {}));

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
    NiceMock<MockCompanionManager> mockCompanionManager_;
    std::shared_ptr<SubscriptionManager> subscriptionManager_;
};

HWTEST_F(ContinuousAuthSubscriptionTest, Create_001, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([](OnCompanionDeviceStatusChange &&callback) { return MakeSubscription(); }));
    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).WillOnce(Return(std::vector<CompanionStatus> {}));

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(ContinuousAuthSubscriptionTest, Create_002, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = 12345;

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([](OnCompanionDeviceStatusChange &&callback) { return MakeSubscription(); }));
    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).WillOnce(Return(std::vector<CompanionStatus> {}));

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(ContinuousAuthSubscriptionTest, Create_003, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_)).WillOnce(Return(nullptr));

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);

    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(ContinuousAuthSubscriptionTest, GetUserId_001, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    EXPECT_EQ(subscription->GetUserId(), userId);
}

HWTEST_F(ContinuousAuthSubscriptionTest, GetTemplateId_001, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = 12345;

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    EXPECT_EQ(subscription->GetTemplateId(), templateId);
}

HWTEST_F(ContinuousAuthSubscriptionTest, GetWeakPtr_001, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    auto weakPtr = subscription->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(ContinuousAuthSubscriptionTest, OnCallbackAdded_001, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    sptr<MockIIpcContinuousAuthStatusCallback> callback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscription->OnCallbackAdded(callback);
}

HWTEST_F(ContinuousAuthSubscriptionTest, OnCallbackAdded_002, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    sptr<MockIIpcContinuousAuthStatusCallback> callback = nullptr;

    subscription->OnCallbackAdded(callback);
}

HWTEST_F(ContinuousAuthSubscriptionTest, HandleCompanionStatusChange_001, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    OnCompanionDeviceStatusChange storedCallback;

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&storedCallback](OnCompanionDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    std::vector<CompanionStatus> companionStatusList = {};

    if (storedCallback) {
        storedCallback(companionStatusList);
    }

    EXPECT_FALSE(subscription->cachedAuthTrustLevel_.has_value());
}

HWTEST_F(ContinuousAuthSubscriptionTest, HandleCompanionStatusChange_002, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    OnCompanionDeviceStatusChange storedCallback;

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&storedCallback](OnCompanionDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    CompanionStatus status {};
    status.hostUserId = userId;
    status.templateId = 12345;
    status.isValid = true;
    status.tokenAtl = 2;

    std::vector<CompanionStatus> companionStatusList = { status };

    if (storedCallback) {
        storedCallback(companionStatusList);
    }

    EXPECT_TRUE(subscription->cachedAuthTrustLevel_.has_value());
    EXPECT_EQ(subscription->cachedAuthTrustLevel_.value(), status.tokenAtl);
}

HWTEST_F(ContinuousAuthSubscriptionTest, HandleCompanionStatusChange_003, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = 12345;
    OnCompanionDeviceStatusChange storedCallback;

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&storedCallback](OnCompanionDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    CompanionStatus status {};
    status.hostUserId = userId;
    status.templateId = templateId.value();
    status.isValid = true;
    status.tokenAtl = 2;

    std::vector<CompanionStatus> companionStatusList = { status };

    if (storedCallback) {
        storedCallback(companionStatusList);
    }

    EXPECT_TRUE(subscription->cachedAuthTrustLevel_.has_value());
    EXPECT_EQ(subscription->cachedAuthTrustLevel_.value(), status.tokenAtl);
}

HWTEST_F(ContinuousAuthSubscriptionTest, HandleCompanionStatusChange_004, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = 12345;
    OnCompanionDeviceStatusChange storedCallback;

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&storedCallback](OnCompanionDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    CompanionStatus status {};
    status.hostUserId = userId;
    status.templateId = 99999;
    status.isValid = true;
    status.tokenAtl = 2;

    std::vector<CompanionStatus> companionStatusList = { status };

    if (storedCallback) {
        storedCallback(companionStatusList);
    }

    EXPECT_FALSE(subscription->cachedAuthTrustLevel_.has_value());
}

HWTEST_F(ContinuousAuthSubscriptionTest, HandleCompanionStatusChange_005, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    OnCompanionDeviceStatusChange storedCallback;

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&storedCallback](OnCompanionDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    CompanionStatus status {};
    status.hostUserId = 200;
    status.templateId = 12345;
    status.isValid = true;
    status.tokenAtl = 2;

    std::vector<CompanionStatus> companionStatusList = { status };

    if (storedCallback) {
        storedCallback(companionStatusList);
    }

    EXPECT_FALSE(subscription->cachedAuthTrustLevel_.has_value());
}

HWTEST_F(ContinuousAuthSubscriptionTest, HandleCompanionStatusChange_006, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    OnCompanionDeviceStatusChange storedCallback;

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&storedCallback](OnCompanionDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    CompanionStatus status {};
    status.hostUserId = userId;
    status.templateId = 12345;
    status.isValid = false;
    status.tokenAtl = std::nullopt;

    std::vector<CompanionStatus> companionStatusList = { status };

    if (storedCallback) {
        storedCallback(companionStatusList);
    }

    EXPECT_FALSE(subscription->cachedAuthTrustLevel_.has_value());
}

HWTEST_F(ContinuousAuthSubscriptionTest, HandleCompanionStatusChange_007, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    OnCompanionDeviceStatusChange storedCallback;

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&storedCallback](OnCompanionDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);
    ASSERT_NE(subscription, nullptr);

    CompanionStatus status1 {};
    status1.hostUserId = userId;
    status1.templateId = 12345;
    status1.isValid = true;
    status1.tokenAtl = 1;

    CompanionStatus status2 {};
    status2.hostUserId = userId;
    status2.templateId = 67890;
    status2.isValid = true;
    status2.tokenAtl = 3;

    std::vector<CompanionStatus> companionStatusList = { status1, status2 };

    if (storedCallback) {
        storedCallback(companionStatusList);
    }

    EXPECT_TRUE(subscription->cachedAuthTrustLevel_.has_value());
    EXPECT_EQ(subscription->cachedAuthTrustLevel_.value(), status2.tokenAtl);
}

HWTEST_F(ContinuousAuthSubscriptionTest, Create_WithNonExistentTemplateId, TestSize.Level0)
{
    // Test creating subscription with templateId that doesn't exist in current user's companions
    // This should still allow subscription creation, as templateId might exist in other users
    UserId userId = 100;
    std::optional<TemplateId> templateId = 99999; // Non-existent templateId

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([](OnCompanionDeviceStatusChange &&callback) { return MakeSubscription(); }));
    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).WillOnce(Return(std::vector<CompanionStatus> {}));

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, subscriptionManager_);

    // Subscription should still be created successfully
    // (actual templateId validation happens at service layer if needed)
    EXPECT_NE(subscription, nullptr);
    if (subscription != nullptr) {
        EXPECT_EQ(subscription->GetUserId(), userId);
        EXPECT_EQ(subscription->GetTemplateId(), templateId);
    }
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
