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

// Fake implementation of RelativeTimer for unit tests

#include "relative_timer.h"

#include <atomic>
#include <functional>
#include <map>
#include <memory>

#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
struct TimerEntry {
    RelativeTimer::TimerCallback callback;
    uint64_t deadlineMs { 0 }; // absolute deadline from time provider
    uint32_t periodMs { 0 };   // 0 = one-shot, >0 = reschedule this far after each fire
};

auto g_pendingTasks = std::make_shared<std::map<uint64_t, TimerEntry>>();
auto g_nextTaskId = std::make_shared<std::atomic<uint64_t>>(0);
std::function<uint64_t()> g_timeProvider = []() { return 0; };

// Fires a single pending timer if its deadline has elapsed. Expired one-shot timers are
// consumed (dropped); periodic timers are rescheduled for their next interval; not-yet-due
// timers are put back to wait. Returns true if the timer fired this pass.
bool TryFireTask(uint64_t now, uint64_t taskId, TimerEntry &entry)
{
    if (!entry.callback || now < entry.deadlineMs) {
        if (entry.callback) {
            (*g_pendingTasks)[taskId] = std::move(entry);
        }
        return false;
    }
    entry.callback();
    if (entry.periodMs > 0) {
        // Reschedule a periodic timer for its next interval so repeated DrainExpiredTasks
        // calls keep firing it (mirrors Utils::Timer).
        entry.deadlineMs = now + entry.periodMs;
        (*g_pendingTasks)[taskId] = std::move(entry);
    }
    return true;
}
} // namespace

RelativeTimer::RelativeTimer()
{
}

RelativeTimer::~RelativeTimer() = default;

std::unique_ptr<Subscription> RelativeTimer::Register(TimerCallback &&callback, uint32_t ms)
{
    uint64_t taskId = (*g_nextTaskId)++;
    auto &entry = (*g_pendingTasks)[taskId];
    entry.callback = std::move(callback);
    entry.deadlineMs = g_timeProvider() + ms;
    return std::make_unique<Subscription>([taskId]() { g_pendingTasks->erase(taskId); });
}

std::unique_ptr<Subscription> RelativeTimer::RegisterPeriodic(TimerCallback &&callback, uint32_t ms)
{
    uint64_t taskId = (*g_nextTaskId)++;
    auto &entry = (*g_pendingTasks)[taskId];
    entry.callback = std::move(callback);
    entry.deadlineMs = g_timeProvider() + ms;
    entry.periodMs = ms;
    return std::make_unique<Subscription>([taskId]() { g_pendingTasks->erase(taskId); });
}

void RelativeTimer::PostTask(TimerCallback &&callback, uint32_t ms)
{
    uint64_t taskId = (*g_nextTaskId)++;
    auto &entry = (*g_pendingTasks)[taskId];
    entry.callback = std::move(callback);
    entry.deadlineMs = g_timeProvider() + ms;
}

void RelativeTimer::ExecuteAll()
{
    auto tasks = std::move(*g_pendingTasks);
    g_pendingTasks->clear();
    for (auto &entry : tasks) {
        if (entry.second.callback) {
            entry.second.callback();
        }
    }
}

void RelativeTimer::EnsureAllTaskExecuted()
{
    const int maxAttempts = 100;
    for (int i = 0; i < maxAttempts; ++i) {
        ExecuteAll();
        if (g_pendingTasks->empty()) {
            return;
        }
    }
}

void RelativeTimer::DrainExpiredTasks()
{
    const int maxAttempts = 100;
    for (int i = 0; i < maxAttempts; ++i) {
        auto tasks = std::move(*g_pendingTasks);
        g_pendingTasks->clear();
        uint64_t now = g_timeProvider();
        bool anyExecuted = false;
        for (auto &entry : tasks) {
            anyExecuted |= TryFireTask(now, entry.first, entry.second);
        }
        if (g_pendingTasks->empty() || !anyExecuted) {
            return;
        }
    }
}

void RelativeTimer::SetTimeProvider(std::function<uint64_t()> provider)
{
    g_timeProvider = std::move(provider);
    // Clear stale timer entries from previous tests.
    // Old deadlines were computed against the previous time source and are invalid.
    g_pendingTasks->clear();
    g_nextTaskId->store(0);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
