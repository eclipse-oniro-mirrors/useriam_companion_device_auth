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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "event_manager_adapter.h"
#include "resident_task_runner.h"
#include "temporary_task_runner.h"
#include "xcollie/xcollie_define.h"
#include "xcollie_helper.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_TASK_RUNNER_MANAGER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
thread_local bool g_runningOnDefaultTaskRunner = false;
constexpr uint32_t TASK_BLOCK_MONITOR_TIMEOUT = 100;

unsigned int ToXCollieFlag(TaskBlockPolicy policy)
{
    return policy == TaskBlockPolicy::REPORT ? HiviewDFX::XCOLLIE_FLAG_LOG : HiviewDFX::XCOLLIE_FLAG_DEFAULT;
}
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

void TaskRunnerManager::CheckRunningOnResidentThread(const char *caller)
{
    ENSURE_OR_RETURN(caller != nullptr);
    if (!RunningOnDefaultTaskRunner()) {
        IAM_LOGE("FATAL: %{public}s not running on resident thread!", caller);
        std::string faultInfo = std::string(caller) + ": Not running on resident thread\nCallStack:\n" + GetCallStack();
        PostTaskOnResident([faultInfo = std::move(faultInfo)]() {
            ReportSystemFault("THREAD_CHECK_FAILED", "THREAD_CHECK", faultInfo);
        });
    }
}

TaskRunnerManager::TaskRunnerManager()
{
    auto taskRunner = std::make_shared<ResidentTaskRunner>();
    ENSURE_OR_RETURN(taskRunner != nullptr);
    taskRunnerMap_.emplace(RESIDENT_TASK_RUNNER_NAME, taskRunner);
}

bool TaskRunnerManager::CreateTaskRunner(const std::string &name, const std::string &owner,
    TaskBlockPolicy policy)
{
    if (name == RESIDENT_TASK_RUNNER_NAME) {
        IAM_LOGE("cannot create resident runner %{public}s via CreateTaskRunner", name.c_str());
        return false;
    }
    if (name.empty() || owner.empty()) {
        IAM_LOGE("empty runner name or owner");
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (taskRunnerMap_.find(name) != taskRunnerMap_.end()) {
        IAM_LOGE("task runner %{public}s already exists", name.c_str());
        return false;
    }
    // RESIDENT always occupies exactly one map slot and has no erase path.
    size_t temporaryCount = taskRunnerMap_.size() - 1;
    if (temporaryCount >= MAX_TMP_RUNNERS) {
        IAM_LOGE("too many temporary task runners %{public}zu, reject %{public}s", temporaryCount, name.c_str());
        return false;
    }
    auto ownerCount = std::count_if(taskRunnerMap_.begin(), taskRunnerMap_.end(),
        [&owner](const auto &entry) { return entry.second->GetOwner() == owner; });
    if (ownerCount >= MAX_TMP_RUNNERS_PER_OWNER) {
        IAM_LOGE("too many runners for owner %{public}s %{public}zu/%{public}zu, reject %{public}s",
            owner.c_str(), ownerCount, MAX_TMP_RUNNERS_PER_OWNER, name.c_str());
        return false;
    }
    std::shared_ptr<TemporaryTaskRunner> taskRunner = std::make_shared<TemporaryTaskRunner>(name, owner, policy);
    ENSURE_OR_RETURN_VAL(taskRunner != nullptr, false);
    taskRunnerMap_.emplace(name, taskRunner);
    IAM_LOGI("task runner %{public}s owner %{public}s create success", name.c_str(), owner.c_str());
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

    auto taskBlockMonitor = std::make_shared<XCollieHelper>("taskBlockMonitor", TASK_BLOCK_MONITOR_TIMEOUT,
        ToXCollieFlag(taskRunner->GetBlockPolicy()));
    ENSURE_OR_RETURN(taskBlockMonitor != nullptr);

    taskRunner->PostTask([taskRunner, taskBlockMonitor, originalTask = std::move(task)]() mutable { originalTask(); });
}

void TaskRunnerManager::PostTaskOnResident(std::function<void()> &&task)
{
    PostTask(RESIDENT_TASK_RUNNER_NAME, std::move(task));
}

bool TaskRunnerManager::RunOnResidentSyncInner(std::function<void()> &&task, uint32_t timeoutSec)
{
    if (RunningOnDefaultTaskRunner()) {
        IAM_LOGI("running on resident task runner");
        task();
        return true;
    }

    IAM_LOGI("post function to default task runner");
    auto promise = std::make_shared<std::promise<void>>();
    ENSURE_OR_RETURN_VAL(promise != nullptr, false);
    auto future = promise->get_future();
    auto cancelled = std::make_shared<std::atomic<bool>>(false);
    ENSURE_OR_RETURN_VAL(cancelled != nullptr, false);
    PostTaskOnResident([task = std::move(task), promise, cancelled]() mutable {
        if (cancelled->load()) {
            IAM_LOGI("RunOnResidentSyncInner task cancelled before execution");
            return;
        }
        task();
        promise->set_value();
    });

#ifdef ENABLE_TEST
    timeoutSec = 0;
#endif
    std::future_status status = future.wait_for(std::chrono::seconds(timeoutSec));
    if (status != std::future_status::ready) {
        IAM_LOGE("RunOnResidentSyncInner timeout - task not completed in %{public}u second, status: %{public}d",
            timeoutSec, static_cast<int32_t>(status));
        cancelled->store(true);
        return false;
    }
    return true;
}

bool TaskRunnerManager::PostOneShotTask(const std::string &owner, TaskBlockPolicy policy,
    std::function<void()> &&task)
{
    static std::atomic<uint32_t> runnerSerial = 1;

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    uint32_t serial = runnerSerial.fetch_add(1);
    std::string runnerName = "OneShot_" + std::to_string(serial);
    if (!CreateTaskRunner(runnerName, owner, policy)) {
        return false;
    }
    PostTask(runnerName, std::move(task));
    DestroyTaskRunner(runnerName);
    return true;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
