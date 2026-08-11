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

#include <memory>

#include "ipc_object_stub.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_guard.h"

#include "common_defines.h"
#include "misc_manager_impl.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class FakeRemoteObject : public IPCObjectStub {
public:
    FakeRemoteObject() : IPCObjectStub(u"FakeRemoteObject")
    {
    }
    ~FakeRemoteObject() override = default;
};

class MockIIpcDeviceSelectCallback : public IIpcDeviceSelectCallback {
public:
    MOCK_METHOD(ErrCode, OnDeviceSelect,
        (int32_t selectPurpose, const sptr<IIpcSetDeviceSelectResultCallback> &callback), (override));
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
};

class MiscManagerImplTest : public Test {
    // No SetUp/TearDown — MockGuard handles it.
};

HWTEST_F(MiscManagerImplTest, Create_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    EXPECT_NE(nullptr, manager);
}

HWTEST_F(MiscManagerImplTest, GetNextGlobalId_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    // Test that IDs are monotonically increasing
    // Note: IDs start from a random value to avoid conflicts, not from 1
    uint64_t id1 = manager->GetNextGlobalId();
    uint64_t id2 = manager->GetNextGlobalId();
    uint64_t id3 = manager->GetNextGlobalId();

    EXPECT_LT(id1, id2);
    EXPECT_LT(id2, id3);
    EXPECT_EQ(id1 + 1, id2);
    EXPECT_EQ(id2 + 1, id3);
}

HWTEST_F(MiscManagerImplTest, GetNextGlobalId_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    // Test that IDs are monotonically increasing
    uint64_t prevId = 0;
    for (int i = 0; i < 100; i++) {
        uint64_t id = manager->GetNextGlobalId();
        ASSERT_GT(id, prevId);
        prevId = id;
    }
}

HWTEST_F(MiscManagerImplTest, SetDeviceSelectCallback_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback);

    sptr<FakeRemoteObject> remoteObj = sptr<FakeRemoteObject>::MakeSptr();
    ASSERT_NE(nullptr, remoteObj);

    EXPECT_CALL(*callback, AsObject()).WillOnce(Return(remoteObj));

    bool result = manager->SetDeviceSelectCallback(tokenId, callback);
    EXPECT_TRUE(result);
}

HWTEST_F(MiscManagerImplTest, SetDeviceSelectCallback_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    bool result = manager->SetDeviceSelectCallback(tokenId, nullptr);
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, SetDeviceSelectCallback_003, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback);

    EXPECT_CALL(*callback, AsObject()).WillOnce(Return(nullptr));

    bool result = manager->SetDeviceSelectCallback(tokenId, callback);
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, SetDeviceSelectCallback_004, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback1 = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    sptr<MockIIpcDeviceSelectCallback> callback2 = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback1);
    ASSERT_NE(nullptr, callback2);

    sptr<FakeRemoteObject> remoteObj1 = sptr<FakeRemoteObject>::MakeSptr();
    sptr<FakeRemoteObject> remoteObj2 = sptr<FakeRemoteObject>::MakeSptr();
    ASSERT_NE(nullptr, remoteObj1);
    ASSERT_NE(nullptr, remoteObj2);

    EXPECT_CALL(*callback1, AsObject()).WillOnce(Return(remoteObj1));
    EXPECT_CALL(*callback2, AsObject()).WillOnce(Return(remoteObj2));

    bool result1 = manager->SetDeviceSelectCallback(tokenId, callback1);
    EXPECT_TRUE(result1);

    bool result2 = manager->SetDeviceSelectCallback(tokenId, callback2);
    EXPECT_TRUE(result2);
}

HWTEST_F(MiscManagerImplTest, GetDeviceDeviceSelectResult_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    SelectPurpose selectPurpose = SelectPurpose::SELECT_ADD_DEVICE;

    auto callbackCalled = std::make_shared<bool>(false);
    DeviceSelectResultHandler resultHandler = [callbackCalled](const std::vector<DeviceKey> &,
                                                  const std::optional<std::vector<uint8_t>> &) {
        *callbackCalled = true;
    };

    bool result = manager->GetDeviceDeviceSelectResult(tokenId, selectPurpose, std::move(resultHandler));
    EXPECT_FALSE(result);
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(MiscManagerImplTest, GetDeviceDeviceSelectResult_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    SelectPurpose selectPurpose = SelectPurpose::SELECT_ADD_DEVICE;

    bool result = manager->GetDeviceDeviceSelectResult(tokenId, selectPurpose, nullptr);
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, GetDeviceDeviceSelectResult_003, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback);

    sptr<FakeRemoteObject> remoteObj = sptr<FakeRemoteObject>::MakeSptr();
    ASSERT_NE(nullptr, remoteObj);

    EXPECT_CALL(*callback, AsObject()).WillOnce(Return(remoteObj));

    bool setResult = manager->SetDeviceSelectCallback(tokenId, callback);
    EXPECT_TRUE(setResult);

    SelectPurpose selectPurpose = SelectPurpose::SELECT_ADD_DEVICE;
    auto callbackCalled = std::make_shared<bool>(false);
    DeviceSelectResultHandler resultHandler = [callbackCalled](const std::vector<DeviceKey> &,
                                                  const std::optional<std::vector<uint8_t>> &) {
        *callbackCalled = true;
    };

    EXPECT_CALL(*callback, OnDeviceSelect(_, _)).WillOnce(Return(ERR_OK));

    bool result = manager->GetDeviceDeviceSelectResult(tokenId, selectPurpose, std::move(resultHandler));
    EXPECT_TRUE(result);
}

HWTEST_F(MiscManagerImplTest, GetDeviceDeviceSelectResult_004, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback);

    sptr<FakeRemoteObject> remoteObj = sptr<FakeRemoteObject>::MakeSptr();
    ASSERT_NE(nullptr, remoteObj);

    EXPECT_CALL(*callback, AsObject()).WillOnce(Return(remoteObj));

    bool setResult = manager->SetDeviceSelectCallback(tokenId, callback);
    EXPECT_TRUE(setResult);

    SelectPurpose selectPurpose = SelectPurpose::SELECT_ADD_DEVICE;
    DeviceSelectResultHandler resultHandler = [](const std::vector<DeviceKey> &,
                                                  const std::optional<std::vector<uint8_t>> &) {};

    EXPECT_CALL(*callback, OnDeviceSelect(_, _)).WillOnce(Return(ERR_INVALID_VALUE));

    bool result = manager->GetDeviceDeviceSelectResult(tokenId, selectPurpose, std::move(resultHandler));
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, ClearDeviceSelectCallback_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback);

    sptr<FakeRemoteObject> remoteObj = sptr<FakeRemoteObject>::MakeSptr();
    ASSERT_NE(nullptr, remoteObj);

    EXPECT_CALL(*callback, AsObject()).WillOnce(Return(remoteObj));

    bool setResult = manager->SetDeviceSelectCallback(tokenId, callback);
    EXPECT_TRUE(setResult);

    manager->ClearDeviceSelectCallback(tokenId);

    SelectPurpose selectPurpose = SelectPurpose::SELECT_ADD_DEVICE;
    DeviceSelectResultHandler resultHandler = [](const std::vector<DeviceKey> &,
                                                  const std::optional<std::vector<uint8_t>> &) {};

    bool result = manager->GetDeviceDeviceSelectResult(tokenId, selectPurpose, std::move(resultHandler));
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, ClearDeviceSelectCallback_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    manager->ClearDeviceSelectCallback(tokenId);
}

HWTEST_F(MiscManagerImplTest, GetLocalUdid_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    auto udid = manager->GetLocalUdid();
    EXPECT_TRUE(udid.has_value());
}

HWTEST_F(MiscManagerImplTest, CompanionAuthBlocked_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    EXPECT_TRUE(manager->IsCompanionAuthBlocked());

    manager->SetCompanionAuthBlocked(false);
    EXPECT_FALSE(manager->IsCompanionAuthBlocked());

    manager->SetCompanionAuthBlocked(false);
    EXPECT_FALSE(manager->IsCompanionAuthBlocked());
}

// SetCompanionAuthBlocked notifies subscribers only on an actual state change,
// delivering the new blocked value; same-value calls and post-unsubscribe do not fire.
HWTEST_F(MiscManagerImplTest, CompanionAuthBlockedChange_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    int blockedCount = 0;
    int unblockedCount = 0;
    auto sub = manager->SubscribeCompanionAuthBlockedChange([&blockedCount, &unblockedCount](bool blocked) {
        if (blocked) {
            ++blockedCount;
        } else {
            ++unblockedCount;
        }
    });
    ASSERT_NE(nullptr, sub);

    // Initial state is blocked; setting blocked again must not fire.
    manager->SetCompanionAuthBlocked(true);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(blockedCount, 0);
    EXPECT_EQ(unblockedCount, 0);

    // Transitioning to unblocked fires once with blocked=false.
    manager->SetCompanionAuthBlocked(false);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(blockedCount, 0);
    EXPECT_EQ(unblockedCount, 1);

    // Transitioning back to blocked fires once with blocked=true.
    manager->SetCompanionAuthBlocked(true);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(blockedCount, 1);
    EXPECT_EQ(unblockedCount, 1);

    // After unsubscribe, no further events are delivered.
    sub.reset();
    manager->SetCompanionAuthBlocked(false);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(blockedCount, 1);
    EXPECT_EQ(unblockedCount, 1);
}

// PushPendingUnlock / TakePendingUnlock gate the [5012] commit. The pending set is keyed by
// scheduleId and bounded to MAX_PENDING_UNLOCK_SCHEDULE_IDS (5): Take returns the templateId stored at
// push time for a pushed schedule and removes it; absent or already-taken schedules return nullopt.
// No TTL.
HWTEST_F(MiscManagerImplTest, PendingUnlock_PushAndTake_001, TestSize.Level0)
{
    MockGuard guard;
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    constexpr uint64_t scheduleId = 0x1234;
    constexpr uint64_t templateId = 0x5678;
    EXPECT_FALSE(manager->TakePendingUnlock(scheduleId).has_value()); // nothing pushed yet
    manager->PushPendingUnlock(scheduleId, templateId);
    EXPECT_EQ(templateId, manager->TakePendingUnlock(scheduleId));    // fresh -> stored templateId
    EXPECT_FALSE(manager->TakePendingUnlock(scheduleId).has_value()); // already taken
}

HWTEST_F(MiscManagerImplTest, PendingUnlock_DistinctSchedules_002, TestSize.Level0)
{
    MockGuard guard;
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->PushPendingUnlock(1, 10);
    manager->PushPendingUnlock(2, 20);
    EXPECT_EQ(20ULL, manager->TakePendingUnlock(2)); // order-independent, returns stored templateId
    EXPECT_EQ(10ULL, manager->TakePendingUnlock(1));
    EXPECT_FALSE(manager->TakePendingUnlock(1).has_value());
    EXPECT_FALSE(manager->TakePendingUnlock(2).has_value());
}

// Re-pushing a schedule that was already taken refreshes it for another take cycle; the templateId
// stored at the latest push is the one returned.
HWTEST_F(MiscManagerImplTest, PendingUnlock_RePush_003, TestSize.Level0)
{
    MockGuard guard;
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    constexpr uint64_t scheduleId = 0xABCD;
    constexpr uint64_t templateId = 0x1111;
    manager->PushPendingUnlock(scheduleId, templateId);
    EXPECT_EQ(templateId, manager->TakePendingUnlock(scheduleId));
    EXPECT_FALSE(manager->TakePendingUnlock(scheduleId).has_value());
    manager->PushPendingUnlock(scheduleId, templateId + 1); // re-push refreshes templateId
    EXPECT_EQ(templateId + 1, manager->TakePendingUnlock(scheduleId));
}

// The pending set holds at most 5 entries; a 6th distinct push evicts the oldest. Re-pushing an
// existing schedule does not grow the list and refreshes its position (so it is not the one evicted next).
HWTEST_F(MiscManagerImplTest, PendingUnlock_EvictOldestAtCap_004, TestSize.Level0)
{
    MockGuard guard;
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    for (uint64_t id = 1; id <= 5; ++id) {
        manager->PushPendingUnlock(id, id * 10);
    }
    manager->PushPendingUnlock(3, 30); // re-push refreshes position to newest, list stays at 5
    manager->PushPendingUnlock(6, 60); // 6th distinct id evicts the oldest still-pending (1)

    EXPECT_FALSE(manager->TakePendingUnlock(1).has_value()); // evicted
    EXPECT_EQ(20ULL, manager->TakePendingUnlock(2));
    EXPECT_EQ(30ULL, manager->TakePendingUnlock(3)); // refreshed, still present
    EXPECT_EQ(40ULL, manager->TakePendingUnlock(4));
    EXPECT_EQ(50ULL, manager->TakePendingUnlock(5));
    EXPECT_EQ(60ULL, manager->TakePendingUnlock(6));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
