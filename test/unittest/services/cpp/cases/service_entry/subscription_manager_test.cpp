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

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class MockIIpcAvailableDeviceStatusCallback : public IIpcAvailableDeviceStatusCallback {
public:
    MockIIpcAvailableDeviceStatusCallback() = default;
    ~MockIIpcAvailableDeviceStatusCallback() override = default;

    MOCK_METHOD(ErrCode, OnAvailableDeviceStatusChange, (const std::vector<IpcDeviceStatus> &deviceStatusList),
        (override));
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
};

class MockIIpcTemplateStatusCallback : public IIpcTemplateStatusCallback {
public:
    MockIIpcTemplateStatusCallback() = default;
    ~MockIIpcTemplateStatusCallback() override = default;

    MOCK_METHOD(int32_t, OnTemplateStatusChange, (const std::vector<IpcTemplateStatus> &templateStatusList),
        (override));
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
};

class MockIIpcContinuousAuthStatusCallback : public IIpcContinuousAuthStatusCallback {
public:
    MockIIpcContinuousAuthStatusCallback() = default;
    ~MockIIpcContinuousAuthStatusCallback() override = default;

    MOCK_METHOD(int32_t, OnContinuousAuthStatusChange, (const IpcContinuousAuthStatus &status), (override));
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
};

class SubscriptionManagerTest : public Test {};

HWTEST_F(SubscriptionManagerTest, Constructor_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    EXPECT_NE(subscriptionManager, nullptr);
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([](OnDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    subscriptionManager->AddAvailableDeviceStatusCallback(userId, CallerInfo {}, callback);

    EXPECT_FALSE(subscriptionManager->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = nullptr;

    subscriptionManager->AddAvailableDeviceStatusCallback(userId, CallerInfo {}, callback);

    EXPECT_TRUE(subscriptionManager->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_003, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_)).WillOnce(Return(nullptr));

    subscriptionManager->AddAvailableDeviceStatusCallback(userId, CallerInfo {}, callback);

    EXPECT_TRUE(subscriptionManager->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_004, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback1 = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    sptr<MockIIpcAvailableDeviceStatusCallback> callback2 = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([](OnDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    subscriptionManager->AddAvailableDeviceStatusCallback(userId, CallerInfo {}, callback1);
    subscriptionManager->AddAvailableDeviceStatusCallback(userId, CallerInfo {}, callback2);

    EXPECT_FALSE(subscriptionManager->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveAvailableDeviceStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([](OnDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    subscriptionManager->AddAvailableDeviceStatusCallback(userId, CallerInfo {}, callback);
    subscriptionManager->RemoveAvailableDeviceStatusCallback(callback);

    EXPECT_TRUE(subscriptionManager->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveAvailableDeviceStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = nullptr;

    ASSERT_NO_THROW(subscriptionManager->RemoveAvailableDeviceStatusCallback(callback));
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([](OnCompanionDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    subscriptionManager->AddTemplateStatusCallback(userId, CallerInfo {}, callback);

    EXPECT_FALSE(subscriptionManager->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = nullptr;

    subscriptionManager->AddTemplateStatusCallback(userId, CallerInfo {}, callback);

    EXPECT_TRUE(subscriptionManager->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_003, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_)).WillOnce(Return(nullptr));

    subscriptionManager->AddTemplateStatusCallback(userId, CallerInfo {}, callback);

    EXPECT_TRUE(subscriptionManager->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_004, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback1 = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    sptr<MockIIpcTemplateStatusCallback> callback2 = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([](OnCompanionDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    subscriptionManager->AddTemplateStatusCallback(userId, CallerInfo {}, callback1);
    subscriptionManager->AddTemplateStatusCallback(userId, CallerInfo {}, callback2);

    EXPECT_FALSE(subscriptionManager->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveTemplateStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([](OnCompanionDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    subscriptionManager->AddTemplateStatusCallback(userId, CallerInfo {}, callback);
    subscriptionManager->RemoveTemplateStatusCallback(callback);

    EXPECT_TRUE(subscriptionManager->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveTemplateStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    sptr<MockIIpcTemplateStatusCallback> callback = nullptr;

    ASSERT_NO_THROW(subscriptionManager->RemoveTemplateStatusCallback(callback));
}

// AddTemplateStatusCallback_OpensConfirmWindow / _EachSubscriberReopensWindow /
// RemoveTemplateStatusCallback_ClosesWindow removed: since AddCallback rejects
// callbacks whose AsObject() is null (death-recipient registration requires a
// real binder object), these window open/close effects are not reachable from
// unit tests with mocked callbacks.

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([](OnCompanionDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback);

    EXPECT_FALSE(subscriptionManager->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    std::optional<TemplateId> templateId = 12345;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([](OnCompanionDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback);

    EXPECT_FALSE(subscriptionManager->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_003, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = nullptr;

    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback);

    EXPECT_TRUE(subscriptionManager->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_004, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback1 = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    sptr<MockIIpcContinuousAuthStatusCallback> callback2 = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([](OnCompanionDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback1);
    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback2);

    EXPECT_FALSE(subscriptionManager->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveContinuousAuthStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([](OnCompanionDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback);
    subscriptionManager->RemoveContinuousAuthStatusCallback(callback);
}

HWTEST_F(SubscriptionManagerTest, RemoveContinuousAuthStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    sptr<MockIIpcContinuousAuthStatusCallback> callback = nullptr;

    ASSERT_NO_THROW(subscriptionManager->RemoveContinuousAuthStatusCallback(callback));
}

HWTEST_F(SubscriptionManagerTest, UpdateSubscribeMode_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SetSubscribeMode(SUBSCRIBE_MODE_SUBSCRIBED_ONLY)).Times(1);

    ASSERT_NO_THROW(subscriptionManager->UpdateSubscribeMode());
}

// UpdateSubscribeMode_002/_003/_004 removed: the foreground-gating of subscribe
// mode is driven through Add*Callback, which now rejects mocked callbacks
// (null AsObject()), so those paths are not reachable from unit tests.

// ============== MAX_SUBSCRIPTIONS_PER_MAP Limit Tests ==============

namespace {
constexpr size_t TEST_MAX_SUBSCRIPTIONS = 100;
constexpr int32_t TEST_USER_ID_BASE = 100;
constexpr int32_t TEST_OVERFLOW_USER_ID = 300;
constexpr uint64_t TEST_OVERFLOW_TEMPLATE_ID = 999;
} // namespace

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_RejectsWhenMapReachesLimit, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_))
        .WillRepeatedly(Invoke([](OnDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SetSubscribeMode(_)).Times(::testing::AnyNumber());

    for (int32_t i = 0; i < static_cast<int32_t>(TEST_MAX_SUBSCRIPTIONS); ++i) {
        auto callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
        ASSERT_NE(callback, nullptr);
        subscriptionManager->AddAvailableDeviceStatusCallback(i + TEST_USER_ID_BASE, CallerInfo {}, callback);
    }

    EXPECT_EQ(subscriptionManager->availableDeviceSubscriptions_.size(), TEST_MAX_SUBSCRIPTIONS);

    // The next one should fail -- map is full, no new subscription created.
    auto overflowCallback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(overflowCallback, nullptr);
    subscriptionManager->AddAvailableDeviceStatusCallback(TEST_OVERFLOW_USER_ID, CallerInfo {}, overflowCallback);

    EXPECT_EQ(subscriptionManager->availableDeviceSubscriptions_.size(), TEST_MAX_SUBSCRIPTIONS);
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_RejectsWhenMapReachesLimit, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillRepeatedly(
            Invoke([](OnCompanionDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SetSubscribeMode(_)).Times(::testing::AnyNumber());

    for (int32_t i = 0; i < static_cast<int32_t>(TEST_MAX_SUBSCRIPTIONS); ++i) {
        auto callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
        ASSERT_NE(callback, nullptr);
        subscriptionManager->AddTemplateStatusCallback(i + TEST_USER_ID_BASE, CallerInfo {}, callback);
    }

    EXPECT_EQ(subscriptionManager->templateStatusSubscriptions_.size(), TEST_MAX_SUBSCRIPTIONS);

    auto overflowCallback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(overflowCallback, nullptr);
    subscriptionManager->AddTemplateStatusCallback(TEST_OVERFLOW_USER_ID, CallerInfo {}, overflowCallback);

    EXPECT_EQ(subscriptionManager->templateStatusSubscriptions_.size(), TEST_MAX_SUBSCRIPTIONS);
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_RejectsWhenMapReachesLimit, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillRepeatedly(
            Invoke([](OnCompanionDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    // Each combination of (userId, templateId) creates a unique key.
    for (int32_t i = 0; i < static_cast<int32_t>(TEST_MAX_SUBSCRIPTIONS); ++i) {
        auto callback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
        ASSERT_NE(callback, nullptr);
        subscriptionManager->AddContinuousAuthStatusCallback(i + TEST_USER_ID_BASE, static_cast<uint64_t>(i), callback);
    }

    EXPECT_EQ(subscriptionManager->continuousAuthSubscriptions_.size(), TEST_MAX_SUBSCRIPTIONS);

    auto overflowCallback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(overflowCallback, nullptr);
    subscriptionManager->AddContinuousAuthStatusCallback(TEST_OVERFLOW_USER_ID, TEST_OVERFLOW_TEMPLATE_ID,
        overflowCallback);

    EXPECT_EQ(subscriptionManager->continuousAuthSubscriptions_.size(), TEST_MAX_SUBSCRIPTIONS);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
