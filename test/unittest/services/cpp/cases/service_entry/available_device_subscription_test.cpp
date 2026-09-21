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
#include "mock_remote_object.h"

#include "available_device_subscription.h"
#include "subscription.h"
#include "subscription_manager.h"
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
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([](OnDeviceStatusChange &&callback) { return MakeSubscription(); }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetAllDeviceStatus(true))
        .WillOnce(Return(std::vector<DeviceStatus> {}));
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { 0, INVALID_SUB_PROFILE_ID }));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(AvailableDeviceSubscriptionTest, Create_002, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_)).WillOnce(Return(nullptr));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);

    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(AvailableDeviceSubscriptionTest, GetUserId_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    EXPECT_EQ(subscription->GetUserId(), userId);
}

HWTEST_F(AvailableDeviceSubscriptionTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    auto weakPtr = subscription->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(AvailableDeviceSubscriptionTest, OnCallbackAdded_001, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
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
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);

    sptr<MockIIpcAvailableDeviceStatusCallback> callback = nullptr;

    subscription->OnCallbackAdded(callback);
}

DeviceStatus MakeUnsyncedStatus(const std::string &deviceId)
{
    DeviceStatus status {};
    status.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    status.deviceKey.deviceId = deviceId;
    status.deviceKey.deviceUserId = INVALID_USER_ID;
    status.deviceName = "name-" + deviceId;
    status.isOnline = false;
    return status;
}

CompanionStatus MakeBoundStatus(UserId hostUserId, const std::string &deviceId, UserId deviceUserId)
{
    CompanionStatus status {};
    status.hostUserKey.userId = hostUserId;
    status.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    status.companionDeviceStatus.deviceKey.deviceId = deviceId;
    status.companionDeviceStatus.deviceKey.deviceUserId = deviceUserId;
    return status;
}

HWTEST_F(AvailableDeviceSubscriptionTest, HandleDeviceStatusChange_ReportUnsyncedUnboundDevice, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    OnDeviceStatusChange storedCallback;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([&storedCallback](OnDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetAllDeviceStatus(true))
        .WillRepeatedly(Return(std::vector<DeviceStatus> { MakeUnsyncedStatus("device-1") }));
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserkey())
        .WillRepeatedly(Return(UserKey { userId, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetCompanionManager(), GetAllCompanionStatus())
        .WillRepeatedly(Return(std::vector<CompanionStatus> {}));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);
    ASSERT_TRUE(storedCallback);

    storedCallback({});

    ASSERT_EQ(1u, subscription->cachedAvailableDeviceStatus_.size());
    EXPECT_EQ("device-1", subscription->cachedAvailableDeviceStatus_[0].deviceKey.deviceId);
    EXPECT_FALSE(subscription->cachedAvailableDeviceStatus_[0].isOnline);
    EXPECT_EQ(INVALID_USER_ID, subscription->cachedAvailableDeviceStatus_[0].deviceKey.deviceUserId);
}

HWTEST_F(AvailableDeviceSubscriptionTest, HandleDeviceStatusChange_SuppressBoundDeviceBeforeSync, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    OnDeviceStatusChange storedCallback;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([&storedCallback](OnDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetAllDeviceStatus(true))
        .WillRepeatedly(Return(std::vector<DeviceStatus> { MakeUnsyncedStatus("device-1") }));
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserkey())
        .WillRepeatedly(Return(UserKey { userId, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetCompanionManager(), GetAllCompanionStatus())
        .WillRepeatedly(Return(std::vector<CompanionStatus> { MakeBoundStatus(userId, "device-1", 200) }));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);
    ASSERT_TRUE(storedCallback);

    storedCallback({});

    EXPECT_TRUE(subscription->cachedAvailableDeviceStatus_.empty());
}

HWTEST_F(AvailableDeviceSubscriptionTest, HandleDeviceStatusChange_ReportDeviceBoundToOtherHostUser, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    OnDeviceStatusChange storedCallback;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([&storedCallback](OnDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetAllDeviceStatus(true))
        .WillRepeatedly(Return(std::vector<DeviceStatus> { MakeUnsyncedStatus("device-1") }));
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserkey())
        .WillRepeatedly(Return(UserKey { userId, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetCompanionManager(), GetAllCompanionStatus())
        .WillRepeatedly(Return(std::vector<CompanionStatus> { MakeBoundStatus(999, "device-1", 200) }));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);
    ASSERT_TRUE(storedCallback);

    storedCallback({});

    EXPECT_EQ(1u, subscription->cachedAvailableDeviceStatus_.size());
}

HWTEST_F(AvailableDeviceSubscriptionTest, HandleDeviceStatusChange_SuppressSyncedBoundDevice, TestSize.Level0)
{
    MockGuard guard;
    auto subscriptionManager = SubscriptionManager::Create();
    UserId userId = 100;
    OnDeviceStatusChange storedCallback;

    DeviceStatus syncedStatus = MakeUnsyncedStatus("device-1");
    syncedStatus.deviceKey.deviceUserId = 200;
    syncedStatus.isOnline = true;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeAllDeviceStatus(_))
        .WillOnce(Invoke([&storedCallback](OnDeviceStatusChange &&callback) {
            storedCallback = std::move(callback);
            return MakeSubscription();
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetAllDeviceStatus(true))
        .WillRepeatedly(Return(std::vector<DeviceStatus> { syncedStatus }));
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserkey())
        .WillRepeatedly(Return(UserKey { userId, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_, _))
        .WillRepeatedly(Return(MakeBoundStatus(userId, "device-1", 200)));

    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    ASSERT_NE(subscription, nullptr);
    ASSERT_TRUE(storedCallback);

    storedCallback({});

    EXPECT_TRUE(subscription->cachedAvailableDeviceStatus_.empty());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
