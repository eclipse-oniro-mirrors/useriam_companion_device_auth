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

#include "blocked_state_sync_scheduler.h"

#include <cstdint>
#include <new>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "common_defines.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "subscription.h"
#include "system_ability_definition.h"
#include "user_id_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_BLOCKED_STATE_SYNC_SCHEDULER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr uint32_t BLOCKED_SYNC_BASE_DELAY_MS = 1000;
constexpr uint32_t BLOCKED_SYNC_MAX_DELAY_MS = 10 * 1000;
constexpr uint32_t BLOCKED_SYNC_MAX_RETRY_COUNT = 10;
} // namespace

std::shared_ptr<BlockedStateSyncScheduler> BlockedStateSyncScheduler::Create()
{
    std::shared_ptr<BlockedStateSyncScheduler> scheduler(new (std::nothrow) BlockedStateSyncScheduler());
    ENSURE_OR_RETURN_VAL(scheduler != nullptr, nullptr);
    if (!scheduler->Init()) {
        IAM_LOGE("BlockedStateSyncScheduler init failed");
        return nullptr;
    }
    return scheduler;
}

bool BlockedStateSyncScheduler::Init()
{
    BackoffRetryTimer::Config cfg { .name = "BlockedState",
        .baseDelayMs = BLOCKED_SYNC_BASE_DELAY_MS,
        .maxDelayMs = BLOCKED_SYNC_MAX_DELAY_MS,
        .maxRetryCount = BLOCKED_SYNC_MAX_RETRY_COUNT };
    blockedSyncTimer_ = std::make_unique<BackoffRetryTimer>(cfg, [weakSelf = weak_from_this()]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->TryQueryBlocked();
    });
    ENSURE_OR_RETURN_VAL(blockedSyncTimer_ != nullptr, false);

    activeUserSubscription_ = GetUserIdManager().SubscribeActiveUserId([weakSelf = weak_from_this()](UserId userId) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->OnActiveUserChanged(userId);
    });
    ENSURE_OR_RETURN_VAL(activeUserSubscription_ != nullptr, false);

    if (!SubscribeSaStatusListeners()) {
        IAM_LOGE("SubscribeSaStatusListeners failed");
        return false;
    }

    UserId initialUserId = GetUserIdManager().GetActiveUserId();
    if (initialUserId != INVALID_USER_ID) {
        OnActiveUserChanged(initialUserId);
    }

    IAM_LOGI("BlockedStateSyncScheduler started");
    return true;
}

bool BlockedStateSyncScheduler::SubscribeSaStatusListeners()
{
#ifndef ENABLE_TEST
    userAuthSaListener_ = SaStatusListener::Create(
        "UserAuthService", SUBSYS_USERIAM_SYS_ABILITY_USERAUTH,
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnUserAuthServiceReady();
        },
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnUserAuthServiceUnavailable();
        });
    if (userAuthSaListener_ == nullptr) {
        IAM_LOGE("failed to subscribe UserAuthService status");
        return false;
    }

    pinSaListener_ = SaStatusListener::Create(
        "PinAuthService", SUBSYS_USERIAM_SYS_ABILITY_PINAUTH,
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnPinAuthServiceReady();
        },
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnPinAuthServiceUnavailable();
        });
    if (pinSaListener_ == nullptr) {
        IAM_LOGE("failed to subscribe PinAuthService status");
        return false;
    }
#endif
    return true;
}

void BlockedStateSyncScheduler::OnActiveUserChanged(UserId userId)
{
    IAM_LOGI("active user changed to %{public}d", userId);
    GetMiscManager().SetCompanionAuthBlocked(true);
    if (blockedSyncTimer_ != nullptr) {
        blockedSyncTimer_->Reset();
    }
    TryQueryBlocked();
}

void BlockedStateSyncScheduler::TryQueryBlocked()
{
    if (!userAuthSaAvailable_ || !pinSaAvailable_) {
        IAM_LOGI("USER_AUTH or PIN_AUTH SA not available, defer GetProperty");
        return;
    }
    UserId userId = GetUserIdManager().GetActiveUserId();
    if (userId == INVALID_USER_ID) {
        IAM_LOGI("active user invalid, defer GetProperty");
        return;
    }
    GetUserAuthAdapter().CheckIsBlocked(userId, [weakSelf = weak_from_this(), userId](bool blocked, bool needTry) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->OnBlockedQueryResult(userId, blocked, needTry);
    });
}

void BlockedStateSyncScheduler::OnBlockedQueryResult(UserId userId, bool blocked, bool needTry)
{
    if (userId != GetUserIdManager().GetActiveUserId()) {
        IAM_LOGI("stale blocked query for %{public}d, discard", userId);
        return;
    }
    GetMiscManager().SetCompanionAuthBlocked(blocked);
    IAM_LOGI("blocked sync user %{public}d blocked=%{public}d needTry=%{public}d", userId, blocked, needTry);
    ENSURE_OR_RETURN(blockedSyncTimer_ != nullptr);
    if (needTry) {
        blockedSyncTimer_->OnFailure();
    } else {
        blockedSyncTimer_->Reset();
    }
}

void BlockedStateSyncScheduler::OnUserAuthServiceReady()
{
    IAM_LOGI("USER_AUTH SA ready");
    userAuthSaAvailable_ = true;
    TryQueryBlocked();
}

void BlockedStateSyncScheduler::OnUserAuthServiceUnavailable()
{
    IAM_LOGI("USER_AUTH SA unavailable");
    userAuthSaAvailable_ = false;
    ENSURE_OR_RETURN(blockedSyncTimer_ != nullptr);
    blockedSyncTimer_->ResetBackoff();
}

void BlockedStateSyncScheduler::OnPinAuthServiceReady()
{
    IAM_LOGI("PIN_AUTH SA ready");
    pinSaAvailable_ = true;
    TryQueryBlocked();
}

void BlockedStateSyncScheduler::OnPinAuthServiceUnavailable()
{
    IAM_LOGI("PIN_AUTH SA unavailable");
    pinSaAvailable_ = false;
    ENSURE_OR_RETURN(blockedSyncTimer_ != nullptr);
    blockedSyncTimer_->ResetBackoff();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
