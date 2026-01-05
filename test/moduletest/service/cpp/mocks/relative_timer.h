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

#ifndef COMPANION_DEVICE_AUTH_TEST_RELATIVE_TIMER_H
#define COMPANION_DEVICE_AUTH_TEST_RELATIVE_TIMER_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>

#include "singleton.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class RelativeTimer final : public Singleton<RelativeTimer> {
public:
    using TimerCallback = std::function<void()>;

    RelativeTimer();
    ~RelativeTimer() override;

    std::unique_ptr<Subscription> Register(TimerCallback &&callback, uint32_t ms);
    std::unique_ptr<Subscription> RegisterPeriodic(TimerCallback &&callback, uint32_t ms);
    void PostTask(TimerCallback &&callback, uint32_t ms);

    void FastForward(uint32_t delayMs);
    void ExecuteExpiredTasks();
    void ExecuteAll();
    void EnsureAllTaskExecuted();
    void Clear();
    uint64_t GetCurrentTime() const;

private:
    uint64_t RegisterTimer(TimerCallback &&callback, uint32_t ms, bool once);

    mutable std::mutex mutex_;
    std::map<uint64_t, int> timers_; // Placeholder to maintain binary compatibility
    uint64_t currentTimeMs_;
    uint64_t nextTimerId_;

    // Timer implementation details
    struct TimerEntry {
        uint64_t timerId;
        uint32_t interval;
        TimerCallback callback;
        bool once;
        uint64_t nextExecuteTime;
    };
    std::map<uint64_t, TimerEntry> timerEntries_;
    std::atomic<uint64_t> currentTime_ { 0 };
    std::atomic<uint64_t> nextId_ { 1 };
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_RELATIVE_TIMER_H
