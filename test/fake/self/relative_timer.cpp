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
auto g_pendingTasks = std::make_shared<std::map<uint64_t, RelativeTimer::TimerCallback>>();
auto g_nextTaskId = std::make_shared<std::atomic<uint64_t>>(0);
} // namespace

RelativeTimer::RelativeTimer()
{
}

RelativeTimer::~RelativeTimer() = default;

std::unique_ptr<Subscription> RelativeTimer::Register(TimerCallback &&callback, uint32_t ms)
{
    (void)ms;
    uint64_t taskId = (*g_nextTaskId)++;
    (*g_pendingTasks)[taskId] = std::move(callback);
    return std::make_unique<Subscription>([taskId]() { g_pendingTasks->erase(taskId); });
}

std::unique_ptr<Subscription> RelativeTimer::RegisterPeriodic(TimerCallback &&callback, uint32_t ms)
{
    return Register(std::move(callback), ms);
}

void RelativeTimer::PostTask(TimerCallback &&callback, uint32_t ms)
{
    (void)ms;
    uint64_t taskId = (*g_nextTaskId)++;
    (*g_pendingTasks)[taskId] = std::move(callback);
}

void RelativeTimer::ExecuteAll()
{
    auto tasks = std::move(*g_pendingTasks);
    g_pendingTasks->clear();
    for (auto &entry : tasks) {
        if (entry.second) {
            entry.second();
        }
    }
}

void RelativeTimer::EnsureAllTaskExecuted()
{
    ExecuteAll();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
