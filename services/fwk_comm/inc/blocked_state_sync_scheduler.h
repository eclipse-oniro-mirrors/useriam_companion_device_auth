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

#ifndef COMPANION_DEVICE_AUTH_BLOCKED_STATE_SYNC_SCHEDULER_H
#define COMPANION_DEVICE_AUTH_BLOCKED_STATE_SYNC_SCHEDULER_H

#include <memory>

#include "nocopyable.h"

#include "backoff_retry_timer.h"
#include "sa_status_listener.h"
#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class BlockedStateSyncScheduler : public std::enable_shared_from_this<BlockedStateSyncScheduler>, public NoCopyable {
public:
    static std::shared_ptr<BlockedStateSyncScheduler> Create();

    ~BlockedStateSyncScheduler() = default;

private:
    BlockedStateSyncScheduler() = default;

    bool Init();

    bool SubscribeSaStatusListeners();

    void OnActiveUserChanged(UserId userId);
    void TryQueryBlocked();
    void OnBlockedQueryResult(UserId userId, bool blocked, bool needTry);
    void OnUserAuthServiceReady();
    void OnUserAuthServiceUnavailable();
    void OnPinAuthServiceReady();
    void OnPinAuthServiceUnavailable();

    std::unique_ptr<Subscription> activeUserSubscription_;
    std::unique_ptr<BackoffRetryTimer> blockedSyncTimer_;
    std::unique_ptr<SaStatusListener> userAuthSaListener_;
    bool userAuthSaAvailable_ = false;
    std::unique_ptr<SaStatusListener> pinSaListener_;
    bool pinSaAvailable_ = false;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_BLOCKED_STATE_SYNC_SCHEDULER_H
