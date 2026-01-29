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

#include "iam_logger.h"

#define LOG_TAG "CDA_SA"

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

bool TaskRunnerManager::CreateTaskRunner(const std::string &name)
{
    (void)name;
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

void TaskRunnerManager::PostTaskOnTemporary(const std::string &name, std::function<void()> &&task)
{
    (void)name;
    uint64_t taskId = (*g_nextTaskId)++;
    (*g_pendingTasks)[taskId] = std::move(task);
}

void TaskRunnerManager::AssertRunningOnResidentThread() const
{
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
