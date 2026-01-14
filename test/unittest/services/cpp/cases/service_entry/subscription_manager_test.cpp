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

class SubscriptionManagerTest : public Test {
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
        ON_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_))
            .WillByDefault(Invoke([](OnCompanionDeviceStatusChange &&callback) { return MakeSubscription(); }));
        ON_CALL(mockCompanionManager_, GetAllCompanionStatus()).WillByDefault(Return(std::vector<CompanionStatus> {}));

        // Set default behaviors for callback mock methods that are called internally
        ON_CALL(MockIIpcAvailableDeviceStatusCallback(), OnAvailableDeviceStatusChange(_)).WillByDefault(Return(0));
        ON_CALL(MockIIpcAvailableDeviceStatusCallback(), AsObject()).WillByDefault(Return(nullptr));
        ON_CALL(MockIIpcContinuousAuthStatusCallback(), OnContinuousAuthStatusChange(_)).WillByDefault(Return(0));
        ON_CALL(MockIIpcContinuousAuthStatusCallback(), AsObject()).WillByDefault(Return(nullptr));
        ON_CALL(MockIIpcTemplateStatusCallback(), OnTemplateStatusChange(_)).WillByDefault(Return(0));
        ON_CALL(MockIIpcTemplateStatusCallback(), AsObject()).WillByDefault(Return(nullptr));

        subscriptionManager_ = std::make_unique<SubscriptionManager>();
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
    std::unique_ptr<SubscriptionManager> subscriptionManager_;
};

HWTEST_F(SubscriptionManagerTest, Constructor_001, TestSize.Level0)
{
    auto manager = std::make_unique<SubscriptionManager>();
    EXPECT_NE(manager, nullptr);
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_001, TestSize.Level0)
{
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager_->AddAvailableDeviceStatusCallback(userId, callback);

    EXPECT_FALSE(subscriptionManager_->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_002, TestSize.Level0)
{
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = nullptr;

    subscriptionManager_->AddAvailableDeviceStatusCallback(userId, callback);

    EXPECT_TRUE(subscriptionManager_->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_003, TestSize.Level0)
{
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeAllDeviceStatus(_)).WillOnce(Return(nullptr));

    subscriptionManager_->AddAvailableDeviceStatusCallback(userId, callback);

    EXPECT_TRUE(subscriptionManager_->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddAvailableDeviceStatusCallback_004, TestSize.Level0)
{
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback1 = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    sptr<MockIIpcAvailableDeviceStatusCallback> callback2 = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);

    subscriptionManager_->AddAvailableDeviceStatusCallback(userId, callback1);
    subscriptionManager_->AddAvailableDeviceStatusCallback(userId, callback2);

    EXPECT_FALSE(subscriptionManager_->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveAvailableDeviceStatusCallback_001, TestSize.Level0)
{
    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager_->AddAvailableDeviceStatusCallback(userId, callback);
    subscriptionManager_->RemoveAvailableDeviceStatusCallback(callback);

    EXPECT_TRUE(subscriptionManager_->availableDeviceSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveAvailableDeviceStatusCallback_002, TestSize.Level0)
{
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = nullptr;

    subscriptionManager_->RemoveAvailableDeviceStatusCallback(callback);
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_001, TestSize.Level0)
{
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager_->AddTemplateStatusCallback(userId, callback);

    EXPECT_FALSE(subscriptionManager_->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_002, TestSize.Level0)
{
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = nullptr;

    subscriptionManager_->AddTemplateStatusCallback(userId, callback);

    EXPECT_TRUE(subscriptionManager_->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_003, TestSize.Level0)
{
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    EXPECT_CALL(mockCompanionManager_, SubscribeCompanionDeviceStatusChange(_)).WillOnce(Return(nullptr));

    subscriptionManager_->AddTemplateStatusCallback(userId, callback);

    EXPECT_TRUE(subscriptionManager_->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddTemplateStatusCallback_004, TestSize.Level0)
{
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback1 = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    sptr<MockIIpcTemplateStatusCallback> callback2 = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);

    subscriptionManager_->AddTemplateStatusCallback(userId, callback1);
    subscriptionManager_->AddTemplateStatusCallback(userId, callback2);

    EXPECT_FALSE(subscriptionManager_->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveTemplateStatusCallback_001, TestSize.Level0)
{
    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager_->AddTemplateStatusCallback(userId, callback);
    subscriptionManager_->RemoveTemplateStatusCallback(callback);

    EXPECT_TRUE(subscriptionManager_->templateStatusSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveTemplateStatusCallback_002, TestSize.Level0)
{
    sptr<MockIIpcTemplateStatusCallback> callback = nullptr;

    subscriptionManager_->RemoveTemplateStatusCallback(callback);
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_001, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager_->AddContinuousAuthStatusCallback(userId, templateId, callback);

    EXPECT_FALSE(subscriptionManager_->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_002, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = 12345;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager_->AddContinuousAuthStatusCallback(userId, templateId, callback);

    EXPECT_FALSE(subscriptionManager_->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_003, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = nullptr;

    subscriptionManager_->AddContinuousAuthStatusCallback(userId, templateId, callback);

    EXPECT_TRUE(subscriptionManager_->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, AddContinuousAuthStatusCallback_004, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback1 = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    sptr<MockIIpcContinuousAuthStatusCallback> callback2 = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback1, nullptr);
    ASSERT_NE(callback2, nullptr);

    subscriptionManager_->AddContinuousAuthStatusCallback(userId, templateId, callback1);
    subscriptionManager_->AddContinuousAuthStatusCallback(userId, templateId, callback2);

    EXPECT_FALSE(subscriptionManager_->continuousAuthSubscriptions_.empty());
}

HWTEST_F(SubscriptionManagerTest, RemoveContinuousAuthStatusCallback_001, TestSize.Level0)
{
    UserId userId = 100;
    std::optional<TemplateId> templateId = std::nullopt;
    sptr<MockIIpcContinuousAuthStatusCallback> callback = sptr<MockIIpcContinuousAuthStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager_->AddContinuousAuthStatusCallback(userId, templateId, callback);
    subscriptionManager_->RemoveContinuousAuthStatusCallback(callback);
}

HWTEST_F(SubscriptionManagerTest, RemoveContinuousAuthStatusCallback_002, TestSize.Level0)
{
    sptr<MockIIpcContinuousAuthStatusCallback> callback = nullptr;

    subscriptionManager_->RemoveContinuousAuthStatusCallback(callback);
}

HWTEST_F(SubscriptionManagerTest, UpdateSubscribeMode_001, TestSize.Level0)
{
    EXPECT_CALL(mockCrossDeviceCommManager_, SetSubscribeMode(SUBSCRIBE_MODE_AUTH)).Times(1);

    subscriptionManager_->UpdateSubscribeMode();
}

HWTEST_F(SubscriptionManagerTest, UpdateSubscribeMode_002, TestSize.Level0)
{
    EXPECT_CALL(mockCrossDeviceCommManager_, SetSubscribeMode(SUBSCRIBE_MODE_MANAGE)).Times(1);

    UserId userId = 100;
    sptr<MockIIpcAvailableDeviceStatusCallback> callback = sptr<MockIIpcAvailableDeviceStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager_->AddAvailableDeviceStatusCallback(userId, callback);
}

HWTEST_F(SubscriptionManagerTest, UpdateSubscribeMode_003, TestSize.Level0)
{
    EXPECT_CALL(mockCrossDeviceCommManager_, SetSubscribeMode(SUBSCRIBE_MODE_MANAGE)).Times(1);

    UserId userId = 100;
    sptr<MockIIpcTemplateStatusCallback> callback = sptr<MockIIpcTemplateStatusCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    subscriptionManager_->AddTemplateStatusCallback(userId, callback);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
