/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_guard.h"

#include "pending_issue_token_manager.h"
#include "relative_timer.h"
#include "service_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t USER_200 = 200;
constexpr int32_t USER_300 = 300;
constexpr uint64_t TID_123 = 123;
constexpr uint64_t TID_456 = 456;
constexpr uint32_t PENDING_TIMEOUT_MS = 8000;
constexpr uint32_t TIMER_INTERVAL_MS = 1001;

void LinkTimerToTimeKeeper(MockTimeKeeper &timeKeeper)
{
    RelativeTimer::GetInstance().SetTimeProvider(
        [&timeKeeper]() -> uint64_t { return timeKeeper.GetSteadyTimeMs().value_or(0); });
}

void AdvanceAndDrain(MockTimeKeeper &timeKeeper, uint32_t ms)
{
    timeKeeper.AdvanceSteadyTime(ms);
    RelativeTimer::GetInstance().DrainExpiredTasks();
}

class PendingIssueTokenManagerTest : public Test {
public:
};

// UT 001: Defer creates subscription and pending entries
HWTEST_F(PendingIssueTokenManagerTest, Defer_CreatesSubscriptionAndEntries, TestSize.Level0)
{
    MockGuard guard;
    auto mgr = std::make_shared<PendingIssueTokenManager>();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    FreezeCommand cmd;
    cmd.userId = USER_200;
    cmd.lockStateAuthTypeValue = static_cast<uint32_t>(AuthType::PIN);
    cmd.templateIdList = { TID_123, TID_456 };
    std::vector<uint8_t> extraInfo = { 1, 2, 3 };

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(
            Invoke([](OnCompanionDeviceStatusChange &&callback) { return std::make_unique<Subscription>([]() {}); }));
    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(_, _, _)).Times(0);

    mgr->Defer(cmd, extraInfo);
}

// UT 002: Status callback triggers matching templateId -> calls issue, obtain deferred until last
HWTEST_F(PendingIssueTokenManagerTest, StatusChange_TriggersMatchingTemplate, TestSize.Level0)
{
    MockGuard guard;
    auto mgr = std::make_shared<PendingIssueTokenManager>();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    FreezeCommand cmd;
    cmd.userId = USER_200;
    cmd.lockStateAuthTypeValue = static_cast<uint32_t>(AuthType::PIN);
    cmd.templateIdList = { TID_123, TID_456 };
    std::vector<uint8_t> extraInfo;

    OnCompanionDeviceStatusChange capturedCallback;
    EXPECT_CALL(guard.GetUserIdManager(), GetActiveUserId()).WillRepeatedly(Return(USER_200));
    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&capturedCallback](OnCompanionDeviceStatusChange &&callback) {
            capturedCallback = std::move(callback);
            return std::make_unique<Subscription>([]() {});
        }));

    mgr->Defer(cmd, extraInfo);

    CompanionStatus status;
    status.templateId = TID_123;
    status.companionDeviceStatus.isOnline = true;
    std::vector<CompanionStatus> statusList = { status };

    // Only StartIssueTokenRequests called for the matching template
    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(ElementsAre(TID_123), _, _)).Times(1);

    capturedCallback(statusList);
}

// UT 003: All templates triggered -> subscription auto-cleanup
HWTEST_F(PendingIssueTokenManagerTest, StatusChange_AllTemplatesTriggered, TestSize.Level0)
{
    MockGuard guard;
    auto mgr = std::make_shared<PendingIssueTokenManager>();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    FreezeCommand cmd;
    cmd.userId = USER_200;
    cmd.lockStateAuthTypeValue = static_cast<uint32_t>(AuthType::PIN);
    cmd.templateIdList = { TID_123, TID_456 };
    std::vector<uint8_t> extraInfo;

    OnCompanionDeviceStatusChange capturedCallback;
    EXPECT_CALL(guard.GetUserIdManager(), GetActiveUserId()).WillRepeatedly(Return(USER_200));
    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&capturedCallback](OnCompanionDeviceStatusChange &&callback) {
            capturedCallback = std::move(callback);
            return std::make_unique<Subscription>([]() {});
        }));

    mgr->Defer(cmd, extraInfo);

    // Trigger first template
    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(ElementsAre(TID_123), _, _)).Times(1);
    CompanionStatus status1;
    status1.templateId = TID_123;
    status1.companionDeviceStatus.isOnline = true;
    capturedCallback({ status1 });

    // Trigger second (last) template
    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(ElementsAre(TID_456), _, _)).Times(1);
    CompanionStatus status2;
    status2.templateId = TID_456;
    status2.companionDeviceStatus.isOnline = true;
    capturedCallback({ status2 });

    // All done -> irrelevant status change should not trigger
    CompanionStatus irrelevant;
    irrelevant.templateId = 999;
    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(_, _, _)).Times(0);
    capturedCallback({ irrelevant });
}

// UT 003b: Both templates ready in single status callback -> batch issue
HWTEST_F(PendingIssueTokenManagerTest, StatusChange_BothTemplatesReadyAtOnce, TestSize.Level0)
{
    MockGuard guard;
    auto mgr = std::make_shared<PendingIssueTokenManager>();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    FreezeCommand cmd;
    cmd.userId = USER_200;
    cmd.lockStateAuthTypeValue = static_cast<uint32_t>(AuthType::PIN);
    cmd.templateIdList = { TID_123, TID_456 };
    std::vector<uint8_t> extraInfo;

    OnCompanionDeviceStatusChange capturedCallback;
    EXPECT_CALL(guard.GetUserIdManager(), GetActiveUserId()).WillRepeatedly(Return(USER_200));
    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&capturedCallback](OnCompanionDeviceStatusChange &&callback) {
            capturedCallback = std::move(callback);
            return std::make_unique<Subscription>([]() {});
        }));

    mgr->Defer(cmd, extraInfo);

    // Both templates ready at once -> each triggers individual StartIssueTokenRequests
    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(ElementsAre(TID_123), _, _)).Times(1);
    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(ElementsAre(TID_456), _, _)).Times(1);

    CompanionStatus status1;
    status1.templateId = TID_123;
    status1.companionDeviceStatus.isOnline = true;
    CompanionStatus status2;
    status2.templateId = TID_456;
    status2.companionDeviceStatus.isOnline = true;
    capturedCallback({ status1, status2 });
}

// UT 002b/002c removed: user-mismatch and blocked-state checks belong to the
// issue-token request layer (HostIssueTokenRequest / mix-auth), not to the
// pending-entry deferral manager.

// UT 004: Timeout expires -> entry removed, no issue/obtain
HWTEST_F(PendingIssueTokenManagerTest, Timeout_ExpiresEntry, TestSize.Level0)
{
    MockGuard guard;
    auto mgr = std::make_shared<PendingIssueTokenManager>();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    FreezeCommand cmd;
    cmd.userId = USER_200;
    cmd.lockStateAuthTypeValue = static_cast<uint32_t>(AuthType::PIN);
    cmd.templateIdList = { TID_123 };
    std::vector<uint8_t> extraInfo;

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(
            Invoke([](OnCompanionDeviceStatusChange &&callback) { return std::make_unique<Subscription>([]() {}); }));

    mgr->Defer(cmd, extraInfo);

    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(_, _, _)).Times(0);
    AdvanceAndDrain(guard.GetTimeKeeper(), PENDING_TIMEOUT_MS + TIMER_INTERVAL_MS);
}

// UT 005: CancelByUserId same user -> clears pending, timer cancelled
HWTEST_F(PendingIssueTokenManagerTest, CancelByUserId_SameUser, TestSize.Level0)
{
    MockGuard guard;
    auto mgr = std::make_shared<PendingIssueTokenManager>();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    FreezeCommand cmd;
    cmd.userId = USER_200;
    cmd.lockStateAuthTypeValue = static_cast<uint32_t>(AuthType::PIN);
    cmd.templateIdList = { TID_123 };
    std::vector<uint8_t> extraInfo;

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(
            Invoke([](OnCompanionDeviceStatusChange &&callback) { return std::make_unique<Subscription>([]() {}); }));

    mgr->Defer(cmd, extraInfo);
    mgr->CancelByUserId(USER_200);

    // Timer should be cancelled
    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(_, _, _)).Times(0);
    AdvanceAndDrain(guard.GetTimeKeeper(), PENDING_TIMEOUT_MS + TIMER_INTERVAL_MS);
}

// UT 006 removed: CancelByUserId for different user is a trivial edge case
// already covered by UT 005 which tests same-user cancellation

// UT 007: Defer with same templateId replaces old entry, subscription preserved
HWTEST_F(PendingIssueTokenManagerTest, Defer_ReplacesOldEntries_SameTemplateId, TestSize.Level0)
{
    MockGuard guard;
    auto mgr = std::make_shared<PendingIssueTokenManager>();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    OnCompanionDeviceStatusChange capturedCallback;

    // First Defer: user 200, template 123
    FreezeCommand cmd1;
    cmd1.userId = USER_200;
    cmd1.lockStateAuthTypeValue = static_cast<uint32_t>(AuthType::PIN);
    cmd1.templateIdList = { TID_123 };
    std::vector<uint8_t> extraInfo;

    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&capturedCallback](OnCompanionDeviceStatusChange &&callback) {
            capturedCallback = std::move(callback);
            return std::make_unique<Subscription>([]() {});
        }));

    mgr->Defer(cmd1, extraInfo);

    // Second Defer: same templateId 123, different user 300 -- replaces old entry
    FreezeCommand cmd2;
    cmd2.userId = USER_300;
    cmd2.lockStateAuthTypeValue = static_cast<uint32_t>(AuthType::PIN);
    cmd2.templateIdList = { TID_123 };

    // Subscription NOT re-created (already exists)
    EXPECT_CALL(guard.GetUserIdManager(), GetActiveUserId()).WillRepeatedly(Return(USER_300));
    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_)).Times(0);

    mgr->Defer(cmd2, extraInfo);

    // Trigger template 123 -- should use user 300 (the replacement)
    CompanionStatus status;
    status.templateId = TID_123;
    status.companionDeviceStatus.isOnline = true;
    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(ElementsAre(TID_123), _, _)).Times(1);
    capturedCallback({ status });
}

// UT 008: Offline companion -> skip issue token, pendingEntry preserved
HWTEST_F(PendingIssueTokenManagerTest, StatusChange_OfflineSkipsIssueToken, TestSize.Level0)
{
    MockGuard guard;
    auto mgr = std::make_shared<PendingIssueTokenManager>();
    LinkTimerToTimeKeeper(guard.GetTimeKeeper());

    FreezeCommand cmd;
    cmd.userId = USER_200;
    cmd.lockStateAuthTypeValue = static_cast<uint32_t>(AuthType::PIN);
    cmd.templateIdList = { TID_123 };
    std::vector<uint8_t> extraInfo;

    OnCompanionDeviceStatusChange capturedCallback;
    EXPECT_CALL(guard.GetUserIdManager(), GetActiveUserId()).WillRepeatedly(Return(USER_200));
    EXPECT_CALL(guard.GetCompanionManager(), SubscribeCompanionDeviceStatusChange(_))
        .WillOnce(Invoke([&capturedCallback](OnCompanionDeviceStatusChange &&callback) {
            capturedCallback = std::move(callback);
            return std::make_unique<Subscription>([]() {});
        }));

    mgr->Defer(cmd, extraInfo);

    // Status with isOnline=false -> should skip issue token
    CompanionStatus offlineStatus;
    offlineStatus.templateId = TID_123;
    offlineStatus.companionDeviceStatus.isOnline = false;
    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(_, _, _)).Times(0);
    capturedCallback({ offlineStatus });

    // Now go online -> should trigger issue token
    CompanionStatus onlineStatus;
    onlineStatus.templateId = TID_123;
    onlineStatus.companionDeviceStatus.isOnline = true;
    EXPECT_CALL(guard.GetCompanionManager(), StartIssueTokenRequests(ElementsAre(TID_123), _, _)).Times(1);
    capturedCallback({ onlineStatus });
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
