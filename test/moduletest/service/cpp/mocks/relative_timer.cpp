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

#include "relative_timer.h"

#include <algorithm>
#include <atomic>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

RelativeTimer::RelativeTimer() : currentTimeMs_(0), nextTimerId_(0)
{
}
RelativeTimer::~RelativeTimer() = default;

std::unique_ptr<Subscription> RelativeTimer::Register(TimerCallback &&callback, uint32_t ms)
{
    if (ms == 0) {
        callback();
        return std::make_unique<Subscription>([]() {});
    }

    uint64_t id;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        id = nextId_++;
        TimerEntry e;
        e.timerId = id;
        e.interval = ms;
        e.callback = std::move(callback);
        e.once = true;
        e.nextExecuteTime = currentTime_.load() + ms;
        timerEntries_[id] = e;
    }

    return std::make_unique<Subscription>([this, id]() {
        std::lock_guard<std::mutex> lock(mutex_);
        timerEntries_.erase(id);
    });
}

std::unique_ptr<Subscription> RelativeTimer::RegisterPeriodic(TimerCallback &&callback, uint32_t ms)
{
    uint64_t id;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        id = nextId_++;
        TimerEntry e;
        e.timerId = id;
        e.interval = ms;
        e.callback = std::move(callback);
        e.once = false;
        e.nextExecuteTime = currentTime_.load() + ms;
        timerEntries_[id] = e;
    }

    return std::make_unique<Subscription>([this, id]() {
        std::lock_guard<std::mutex> lock(mutex_);
        timerEntries_.erase(id);
    });
}

void RelativeTimer::PostTask(TimerCallback &&callback, uint32_t ms)
{
    if (ms == 0) {
        callback();
    } else {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t id = nextId_++;
        TimerEntry e;
        e.timerId = id;
        e.interval = ms;
        e.callback = std::move(callback);
        e.once = true;
        e.nextExecuteTime = currentTime_.load() + ms;
        timerEntries_[id] = e;
    }
}

void RelativeTimer::FastForward(uint32_t delayMs)
{
    currentTime_.store(currentTime_.load() + delayMs);
    ExecuteExpiredTasks();
}

void RelativeTimer::ExecuteExpiredTasks()
{
    while (true) {
        uint64_t id = 0;
        TimerCallback callback;
        bool found = false;
        bool once = false;
        uint32_t interval = 0;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            uint64_t earliest = UINT64_MAX;
            uint64_t currentTime = currentTime_.load();

            for (auto &[tid, entry] : timerEntries_) {
                if (entry.nextExecuteTime <= currentTime && entry.nextExecuteTime < earliest) {
                    earliest = entry.nextExecuteTime;
                    id = tid;
                    callback = entry.callback;
                    once = entry.once;
                    interval = entry.interval;
                    found = true;
                }
            }
        }

        if (!found || !callback) {
            break;
        }

        callback();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (timerEntries_.find(id) != timerEntries_.end()) {
                if (once || interval == 0) {
                    timerEntries_.erase(id);
                } else {
                    timerEntries_[id].nextExecuteTime += interval;
                }
            }
        }
    }
}

void RelativeTimer::ExecuteAll()
{
    // Temporarily set current time to max to execute all registered timers
    uint64_t savedTime = currentTime_.load();
    currentTime_.store(UINT64_MAX);
    ExecuteExpiredTasks();
    currentTime_.store(savedTime);
}

void RelativeTimer::EnsureAllTaskExecuted()
{
    ExecuteAll();
}

void RelativeTimer::Clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    timerEntries_.clear();
    currentTime_.store(0);
}

uint64_t RelativeTimer::GetCurrentTime() const
{
    return currentTime_.load();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
