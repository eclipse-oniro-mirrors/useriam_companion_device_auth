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

#include <cstdint>
#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_guard.h"

#include "blocked_state_sync_scheduler.h"
#include "relative_timer.h"
#include "service_common.h"
#include "user_auth_adapter.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t USER_100 = 100;
constexpr int32_t USER_200 = 200;
constexpr uint32_t RETRY_DELAY_MS = 1000; // BLOCKED_SYNC_BASE_DELAY_MS

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

class BlockedStateSyncSchedulerTest : public Test {
protected:
    void SetUp() override
    {
        guard_ = std::make_unique<MockGuard>();
        LinkTimerToTimeKeeper(guard_->GetTimeKeeper());
        // No active user during Create(): Init() skips OnActiveUserChanged, so construction has no query
        // side effects and each test drives state explicitly.
        ON_CALL(guard_->GetUserIdManager(), GetActiveUserId()).WillByDefault(Return(INVALID_USER_ID));
        // Provide an explicit no-op action: relying on gmock's built-in PerformDefaultAction trips a
        // CFI indirect-call check on this device and aborts the whole test binary.
        ON_CALL(guard_->GetMiscManager(), SetCompanionAuthBlocked(_)).WillByDefault(Invoke([](bool) {}));
    }

    void TearDown() override
    {
        guard_.reset();
    }

    void SetActiveUser(int32_t userId)
    {
        ON_CALL(guard_->GetUserIdManager(), GetActiveUserId()).WillByDefault(Return(userId));
    }

    std::unique_ptr<MockGuard> guard_;
};

// UT 001: under ENABLE_TEST the SA-status-listener subscribe is skipped, so Create() succeeds without SAMgr.
HWTEST_F(BlockedStateSyncSchedulerTest, Create_Succeeds, TestSize.Level0)
{
    auto sched = BlockedStateSyncScheduler::Create();
    EXPECT_NE(sched, nullptr);
}

// UT 002: only USER_AUTH SA ready -> query deferred.
HWTEST_F(BlockedStateSyncSchedulerTest, OnlyUserAuthReady_NoQuery, TestSize.Level0)
{
    auto sched = BlockedStateSyncScheduler::Create();
    ASSERT_NE(sched, nullptr);

    SetActiveUser(USER_100);
    EXPECT_CALL(guard_->GetUserAuthAdapter(), CheckIsBlocked(_, _)).Times(0);
    sched->OnUserAuthServiceReady();
}

// UT 003: only PIN SA ready -> query deferred.
HWTEST_F(BlockedStateSyncSchedulerTest, OnlyPinReady_NoQuery, TestSize.Level0)
{
    auto sched = BlockedStateSyncScheduler::Create();
    ASSERT_NE(sched, nullptr);

    SetActiveUser(USER_100);
    EXPECT_CALL(guard_->GetUserAuthAdapter(), CheckIsBlocked(_, _)).Times(0);
    sched->OnPinAuthServiceReady();
}

// UT 004: both SAs ready but no valid active user -> query deferred.
HWTEST_F(BlockedStateSyncSchedulerTest, BothReady_InvalidUser_NoQuery, TestSize.Level0)
{
    auto sched = BlockedStateSyncScheduler::Create();
    ASSERT_NE(sched, nullptr);

    EXPECT_CALL(guard_->GetUserAuthAdapter(), CheckIsBlocked(_, _)).Times(0);
    sched->OnUserAuthServiceReady();
    sched->OnPinAuthServiceReady();
}

// UT 005: both SAs ready + valid user -> CheckIsBlocked fires, and blocked=false is propagated.
HWTEST_F(BlockedStateSyncSchedulerTest, BothReady_NotBlocked_PropagatesFalse, TestSize.Level0)
{
    auto sched = BlockedStateSyncScheduler::Create();
    ASSERT_NE(sched, nullptr);

    SetActiveUser(USER_100);
    EXPECT_CALL(guard_->GetUserAuthAdapter(), CheckIsBlocked(USER_100, _))
        .WillOnce(Invoke([](int32_t, CheckBlockedCallback &&cb) { cb(false, false); }));
    EXPECT_CALL(guard_->GetMiscManager(), SetCompanionAuthBlocked(false)).Times(1);

    sched->OnUserAuthServiceReady();
    sched->OnPinAuthServiceReady();
}

// UT 006: query returns blocked=true, needTry=true (transient error) -> blocked state set, and the
// retry re-queries after the delay. needTry, not blocked, is what drives the retry.
HWTEST_F(BlockedStateSyncSchedulerTest, BlockedTrue_Retries, TestSize.Level0)
{
    auto sched = BlockedStateSyncScheduler::Create();
    ASSERT_NE(sched, nullptr);

    SetActiveUser(USER_100);
    // Initial query + one scheduled retry after RETRY_DELAY_MS.
    EXPECT_CALL(guard_->GetUserAuthAdapter(), CheckIsBlocked(USER_100, _))
        .Times(2)
        .WillRepeatedly(Invoke([](int32_t, CheckBlockedCallback &&cb) { cb(true, true); }));
    EXPECT_CALL(guard_->GetMiscManager(), SetCompanionAuthBlocked(true)).Times(2);

    sched->OnUserAuthServiceReady();
    sched->OnPinAuthServiceReady();
    AdvanceAndDrain(guard_->GetTimeKeeper(), RETRY_DELAY_MS);
}

// UT 007: USER_AUTH SA drops after being ready -> subsequent attempts defer until it returns.
HWTEST_F(BlockedStateSyncSchedulerTest, UserAuthUnavailable_DefersUntilBack, TestSize.Level0)
{
    auto sched = BlockedStateSyncScheduler::Create();
    ASSERT_NE(sched, nullptr);

    SetActiveUser(USER_100);
    EXPECT_CALL(guard_->GetUserAuthAdapter(), CheckIsBlocked(USER_100, _))
        .Times(2)
        .WillRepeatedly(Invoke([](int32_t, CheckBlockedCallback &&cb) { cb(false, false); }));

    sched->OnUserAuthServiceReady();
    sched->OnPinAuthServiceReady();                           // first query
    sched->OnUserAuthServiceUnavailable();                    // USER_AUTH drops -> deferred
    AdvanceAndDrain(guard_->GetTimeKeeper(), RETRY_DELAY_MS); // nothing pending (not-blocked resets)
    sched->OnUserAuthServiceReady();                          // USER_AUTH back -> second query
}

// UT 008: PIN SA drops after being ready -> subsequent attempts defer until it returns.
HWTEST_F(BlockedStateSyncSchedulerTest, PinUnavailable_DefersUntilBack, TestSize.Level0)
{
    auto sched = BlockedStateSyncScheduler::Create();
    ASSERT_NE(sched, nullptr);

    SetActiveUser(USER_100);
    EXPECT_CALL(guard_->GetUserAuthAdapter(), CheckIsBlocked(USER_100, _))
        .Times(2)
        .WillRepeatedly(Invoke([](int32_t, CheckBlockedCallback &&cb) { cb(false, false); }));

    sched->OnUserAuthServiceReady();
    sched->OnPinAuthServiceReady();       // first query
    sched->OnPinAuthServiceUnavailable(); // PIN drops -> deferred
    AdvanceAndDrain(guard_->GetTimeKeeper(), RETRY_DELAY_MS);
    sched->OnPinAuthServiceReady(); // PIN back -> second query
}

// UT 009: an active-user switch (delivered through the subscription callback) re-triggers the query
// once both SAs are ready, with the optimistic blocked=true set on the new user.
HWTEST_F(BlockedStateSyncSchedulerTest, ActiveUserChange_TriggersQueryForNewUser, TestSize.Level0)
{
    ActiveUserIdCallback userCb;
    EXPECT_CALL(guard_->GetUserIdManager(), SubscribeActiveUserId(_))
        .WillOnce(DoAll(SaveArg<0>(&userCb),
            Invoke([](ActiveUserIdCallback &&) { return std::make_unique<Subscription>([] {}); })));

    auto sched = BlockedStateSyncScheduler::Create();
    ASSERT_NE(sched, nullptr);
    ASSERT_NE(userCb, nullptr);

    sched->OnUserAuthServiceReady();
    sched->OnPinAuthServiceReady();

    SetActiveUser(USER_200);
    EXPECT_CALL(guard_->GetUserAuthAdapter(), CheckIsBlocked(USER_200, _))
        .WillOnce(Invoke([](int32_t, CheckBlockedCallback &&cb) { cb(false, false); }));
    // Optimistic blocked=true on switch, then false once the query returns.
    EXPECT_CALL(guard_->GetMiscManager(), SetCompanionAuthBlocked(true)).Times(1);
    EXPECT_CALL(guard_->GetMiscManager(), SetCompanionAuthBlocked(false)).Times(1);

    userCb(USER_200);
}

// UT 010: blocked=true but needTry=false (e.g. NOT_ENROLLED) -> blocked state is set, but no retry
// is scheduled because the state is stable and re-querying would not change it.
HWTEST_F(BlockedStateSyncSchedulerTest, BlockedWithoutRetry_StopsPolling, TestSize.Level0)
{
    auto sched = BlockedStateSyncScheduler::Create();
    ASSERT_NE(sched, nullptr);

    SetActiveUser(USER_100);
    // needTry=false -> exactly one query, no scheduled retry.
    EXPECT_CALL(guard_->GetUserAuthAdapter(), CheckIsBlocked(USER_100, _))
        .WillOnce(Invoke([](int32_t, CheckBlockedCallback &&cb) { cb(true, false); }));
    // NOT_ENROLL is still a block, even though it must not trigger polling.
    EXPECT_CALL(guard_->GetMiscManager(), SetCompanionAuthBlocked(true)).Times(1);

    sched->OnUserAuthServiceReady();
    sched->OnPinAuthServiceReady();
    AdvanceAndDrain(guard_->GetTimeKeeper(), RETRY_DELAY_MS);
}

// UT 011: an active user is already present at construction while the SA status listeners are unavailable
// (the unit-test default: the subscribe is skipped under ENABLE_TEST). Init optimistically marks the boot
// user blocked=true and, with no SA-ready signal ever arriving, stays fail-closed: no GetProperty query
// fires and the blocked state is never cleared. Locks the safe-degradation contract for the listener-failure
// path called out in review.
HWTEST_F(BlockedStateSyncSchedulerTest, BootUser_NoSaReady_StaysFailClosed, TestSize.Level0)
{
    SetActiveUser(USER_100); // active user present *during* Create()
    EXPECT_CALL(guard_->GetUserAuthAdapter(), CheckIsBlocked(_, _)).Times(0);
    EXPECT_CALL(guard_->GetMiscManager(), SetCompanionAuthBlocked(true)).Times(1);
    EXPECT_CALL(guard_->GetMiscManager(), SetCompanionAuthBlocked(false)).Times(0);

    auto sched = BlockedStateSyncScheduler::Create();
    ASSERT_NE(sched, nullptr);

    AdvanceAndDrain(guard_->GetTimeKeeper(), RETRY_DELAY_MS); // nothing scheduled; stays fail-closed
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
