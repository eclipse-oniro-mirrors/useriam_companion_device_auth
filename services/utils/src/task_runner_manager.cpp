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

#include "task_runner_manager.h"

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "resident_task_runner.h"
#include "temporary_task_runner.h"
#include "xcollie_helper.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
thread_local bool g_runningOnDefaultTaskRunner = false;
constexpr uint32_t TASK_BLOCK_MONITOR_TIMEOUT = 20;
} // namespace

TaskRunnerManager &TaskRunnerManager::GetInstance()
{
    static TaskRunnerManager defaultInstance;
    return defaultInstance;
}

bool TaskRunnerManager::RunningOnDefaultTaskRunner() const
{
    return g_runningOnDefaultTaskRunner;
}

void TaskRunnerManager::SetRunningOnDefaultTaskRunner(bool value)
{
    g_runningOnDefaultTaskRunner = value;
}

void TaskRunnerManager::AssertRunningOnResidentThread() const
{
    if (!RunningOnDefaultTaskRunner()) {
        IAM_LOGF("FATAL: Not running on resident thread! This violates the design principle");
    }
}

TaskRunnerManager::TaskRunnerManager()
{
    auto taskRunner = std::make_shared<ResidentTaskRunner>();
    ENSURE_OR_RETURN(taskRunner != nullptr);
    taskRunnerMap_.emplace(RESIDENT_TASK_RUNNER_NAME, taskRunner);
}

bool TaskRunnerManager::CreateTaskRunner(const std::string &name)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (taskRunnerMap_.find(name) != taskRunnerMap_.end()) {
        IAM_LOGE("task runner %{public}s already exists", name.c_str());
        return false;
    }
    auto taskRunner = std::make_shared<TemporaryTaskRunner>(name, true);
    ENSURE_OR_RETURN_VAL(taskRunner != nullptr, false);
    taskRunnerMap_.emplace(name, taskRunner);
    IAM_LOGI("task runner %{public}s create success", name.c_str());
    return true;
}

void TaskRunnerManager::DestroyTaskRunner(const std::string &name)
{
    if (name == RESIDENT_TASK_RUNNER_NAME) {
        IAM_LOGE("task runner %{public}s cannot destroy", name.c_str());
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (taskRunnerMap_.find(name) == taskRunnerMap_.end()) {
        IAM_LOGE("task runner %{public}s not exist", name.c_str());
        return;
    }

    auto taskRunner = taskRunnerMap_[name];
    ENSURE_OR_RETURN(taskRunner != nullptr);
    taskRunner->PostTask([name]() {
        auto taskRunner = TaskRunnerManager::GetInstance().GetTaskRunner(RESIDENT_TASK_RUNNER_NAME);
        ENSURE_OR_RETURN(taskRunner != nullptr);
        taskRunner->PostTask([name]() {
            TaskRunnerManager::GetInstance().DeleteTaskRunner(name);
            IAM_LOGI("task runner %{public}s deleted", name.c_str());
        });
        IAM_LOGI("task runner %{public}s delete task posted", name.c_str());
    });
    taskRunner->Suspend();
    IAM_LOGI("task runner %{public}s destroy started", name.c_str());
}

void TaskRunnerManager::DeleteTaskRunner(const std::string &name)
{
    if (name == RESIDENT_TASK_RUNNER_NAME) {
        IAM_LOGE("task runner %{public}s cannot delete", name.c_str());
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (taskRunnerMap_.find(name) == taskRunnerMap_.end()) {
        IAM_LOGE("task runner %{public}s not exist", name.c_str());
        return;
    }

    taskRunnerMap_.erase(name);
    IAM_LOGI("task runner %{public}s is deleted", name.c_str());
}

std::shared_ptr<TaskRunner> TaskRunnerManager::GetTaskRunner(const std::string &name)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (taskRunnerMap_.find(name) == taskRunnerMap_.end()) {
        IAM_LOGE("task runner %{public}s not exist", name.c_str());
        return nullptr;
    }
    return taskRunnerMap_[name];
}

void TaskRunnerManager::PostTask(const std::string &name, std::function<void()> &&task)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (taskRunnerMap_.find(name) == taskRunnerMap_.end()) {
        IAM_LOGE("task runner %{public}s not exist", name.c_str());
        return;
    }
    auto taskRunner = taskRunnerMap_[name];
    ENSURE_OR_RETURN(taskRunner != nullptr);

    auto taskBlockMonitor = std::make_shared<XCollieHelper>("taskBlockMonitor", TASK_BLOCK_MONITOR_TIMEOUT);
    ENSURE_OR_RETURN(taskBlockMonitor != nullptr);

    taskRunner->PostTask([taskRunner, taskBlockMonitor, originalTask = std::move(task)]() mutable {
        originalTask();
        taskRunner->PostTask([taskBlockMonitor]() mutable { (void)taskBlockMonitor; });
    });
}

void TaskRunnerManager::PostTaskOnResident(std::function<void()> &&task)
{
    PostTask(RESIDENT_TASK_RUNNER_NAME, std::move(task));
}

void TaskRunnerManager::PostTaskOnTemporary(const std::string &name, std::function<void()> &&task)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    static std::atomic<uint32_t> serial = 0;
    uint32_t thisSerial = serial.fetch_add(1);
    std::string thread_name = name + "_" + std::to_string(thisSerial);
    CreateTaskRunner(thread_name);
    PostTask(thread_name, std::move(task));
    DestroyTaskRunner(thread_name);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
