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

// Keep the file name under services/fake/, but provide a functional TaskRunnerManager

#include "task_runner_manager.h"

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <string>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
auto g_pendingTasks = std::make_shared<std::map<uint64_t, TaskRunner::Task>>();
auto g_nextTaskId = std::make_shared<std::atomic<uint64_t>>(0);
} // namespace

TaskRunnerManager &TaskRunnerManager::GetInstance()
{
    static TaskRunnerManager instance;
    return instance;
}

TaskRunnerManager::TaskRunnerManager() = default;

bool TaskRunnerManager::RunningOnDefaultTaskRunner() const
{
    return true;
}

void TaskRunnerManager::SetRunningOnDefaultTaskRunner(bool value)
{
    (void)value;
}

// The fake is a deterministic queue for UT/FUZZ: posted tasks wait in g_pendingTasks until
// ExecuteAll/EnsureAllTaskExecuted drains them, sync callables run inline. It never rejects
// work — admission caps and watchdog policy are resource defenses of the real implementation
// (excluded from test builds) and must not be mirrored here: a rejecting fake would make test
// outcomes depend on runner state leaked by earlier cases.
bool TaskRunnerManager::CreateTaskRunner(const std::string &name, const std::string &owner,
    TaskBlockPolicy policy)
{
    (void)name;
    (void)owner;
    (void)policy;
    return true;
}

void TaskRunnerManager::DestroyTaskRunner(const std::string &name)
{
    (void)name;
}

void TaskRunnerManager::DeleteTaskRunner(const std::string &name)
{
    (void)name;
}

std::shared_ptr<TaskRunner> TaskRunnerManager::GetTaskRunner(const std::string &name)
{
    (void)name;
    return nullptr;
}

void TaskRunnerManager::PostTask(const std::string &name, std::function<void()> &&task)
{
    (void)name;
    uint64_t taskId = (*g_nextTaskId)++;
    (*g_pendingTasks)[taskId] = std::move(task);
}

void TaskRunnerManager::PostTaskOnResident(std::function<void()> &&task)
{
    uint64_t taskId = (*g_nextTaskId)++;
    (*g_pendingTasks)[taskId] = std::move(task);
}

bool TaskRunnerManager::RunOnResidentSyncInner(std::function<void()> &&task, uint32_t timeoutSec)
{
    (void)timeoutSec;
    task();
    return true;
}

bool TaskRunnerManager::PostOneShotTask(const std::string &owner, TaskBlockPolicy policy,
    std::function<void()> &&task)
{
    (void)owner;
    (void)policy;
    uint64_t taskId = (*g_nextTaskId)++;
    (*g_pendingTasks)[taskId] = std::move(task);
    return true;
}

void TaskRunnerManager::CheckRunningOnResidentThread(const char *caller)
{
    (void)caller;
    return;
}

void TaskRunnerManager::ExecuteAll()
{
    auto tasks = std::move(*g_pendingTasks);
    g_pendingTasks->clear();
    for (auto &entry : tasks) {
        if (entry.second) {
            entry.second();
        }
    }
}

void TaskRunnerManager::EnsureAllTaskExecuted()
{
    const int maxAttempts = 100;
    for (int i = 0; i < maxAttempts; ++i) {
        ExecuteAll();
        if (g_pendingTasks->empty()) {
            return;
        }
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
