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
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    EXPECT_NE(subscriptionManager, nullptr);
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager->AddAvailableDeviceStatusCallback(userId, callback);

    EXPECT_FALSE(subscriptionManager->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = nullptr;

    subscriptionManager->AddAvailableDeviceStatusCallback(userId, callback);

    EXPECT_TRUE(subscriptionManager->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_003, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_)).WillOnce(Return(nullptr));

    subscriptionManager->AddAvailableDeviceStatusCallback(userId, callback);

    EXPECT_TRUE(subscriptionManager->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_004, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback1 = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    sptr<MockIIpcAvailableDeviceStatusCallback> callback2 = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);

    subscriptionManager->AddAvailableDeviceStatusCallback(userId, callback1);
    subscriptionManager->AddAvailableDeviceStatusCallback(userId, callback2);

    EXPECT_FALSE(subscriptionManager->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveAvailableDeviceStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager->AddAvailableDeviceStatusCallback(userId, callback);
    subscriptionManager->RemoveAvailableDeviceStatusCallback(callback);

    EXPECT_TRUE(subscriptionManager->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveAvailableDeviceStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = nullptr;

    subscriptionManager->RemoveAvailableDeviceStatusCallback(callback);
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager->AddTemplateStatusCallback(userId, callback);

    EXPECT_FALSE(subscriptionManager->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = nullptr;

    subscriptionManager->AddTemplateStatusCallback(userId, callback);

    EXPECT_TRUE(subscriptionManager->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_003, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_)).WillOnce(Return(nullptr));

    subscriptionManager->AddTemplateStatusCallback(userId, callback);

    EXPECT_TRUE(subscriptionManager->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_004, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback1 = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    sptr<MockIIpcTemplateStatusCallback> callback2 = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);

    subscriptionManager->AddTemplateStatusCallback(userId, callback1);
    subscriptionManager->AddTemplateStatusCallback(userId, callback2);

    EXPECT_FALSE(subscriptionManager->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveTemplateStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager->AddTemplateStatusCallback(userId, callback);
    subscriptionManager->RemoveTemplateStatusCallback(callback);

    EXPECT_TRUE(subscriptionManager->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveTemplateStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    sptr<MockIIpcTemplateStatusCallback> callback = nullptr;

    subscriptionManager->RemoveTemplateStatusCallback(callback);
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback);

    EXPECT_FALSE(subscriptionManager->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    std::optional<TemplateId> templateId = 12345;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback);

    EXPECT_FALSE(subscriptionManager->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_003, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = nullptr;

    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback);

    EXPECT_TRUE(subscriptionManager->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_004, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback1 = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    sptr<MockIIpcContinuousAuthStatusCallback> callback2 = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);

    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback1);
    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback2);

    EXPECT_FALSE(subscriptionManager->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveContinuousAuthStatusCallback_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager->AddContinuousAuthStatusCallback(userId, templateId, callback);
    subscriptionManager->RemoveContinuousAuthStatusCallback(callback);
}

HWTEST_F(SubscriptionManagerTest, RemoveContinuousAuthStatusCallback_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    sptr<MockIIpcContinuousAuthStatusCallback> callback = nullptr;

    subscriptionManager->RemoveContinuousAuthStatusCallback(callback);
}

HWTEST_F(SubscriptionManagerTest, UpdateSubscribeMode_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SetSubscribeMode(SUBSCRIBE_MODE_AUTH)).Times(1);

    subscriptionManager->UpdateSubscribeMode();
}

HWTEST_F(SubscriptionManagerTest, UpdateSubscribeMode_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SetSubscribeMode(SUBSCRIBE_MODE_MANAGE)).Times(1);

    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager->AddAvailableDeviceStatusCallback(userId, callback);
}

HWTEST_F(SubscriptionManagerTest, UpdateSubscribeMode_003, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = std::make_unique<SubscriptionManager>();
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SetSubscribeMode(SUBSCRIBE_MODE_MANAGE)).Times(1);

    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager->AddTemplateStatusCallback(userId, callback);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
