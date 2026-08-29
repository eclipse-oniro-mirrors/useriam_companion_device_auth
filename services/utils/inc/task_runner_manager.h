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

#ifndef COMPANION_DEVICE_AUTH_TASK_RUNNER_MANAGER_H
#define COMPANION_DEVICE_AUTH_TASK_RUNNER_MANAGER_H

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "task_runner.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

const std::string RESIDENT_TASK_RUNNER_NAME = "ResidentRunner";

constexpr size_t MAX_TMP_RUNNERS_PER_OWNER = 3;
constexpr size_t MAX_TMP_RUNNERS = 12;

constexpr uint32_t MAX_RESIDENT_SYNC_TIMEOUT_SEC = 2;

template <typename T>
struct ResidentSyncResult {
    using type = std::optional<T>;
};

template <>
struct ResidentSyncResult<void> {
    using type = bool; // void callable has no value to carry; success/failure only
};

class TaskRunnerManager {
public:
    static TaskRunnerManager &GetInstance();

    TaskRunnerManager();
    virtual ~TaskRunnerManager() = default;

    virtual bool RunningOnDefaultTaskRunner() const;
    void SetRunningOnDefaultTaskRunner(bool value);
    void CheckRunningOnResidentThread(const char *caller);

    virtual bool CreateTaskRunner(const std::string &name, const std::string &owner,
        TaskBlockPolicy policy = TaskBlockPolicy::FATAL);
    virtual void DestroyTaskRunner(const std::string &name);
    virtual void DeleteTaskRunner(const std::string &name);
    virtual std::shared_ptr<TaskRunner> GetTaskRunner(const std::string &name);
    virtual void PostTask(const std::string &name, std::function<void()> &&task);
    virtual void PostTaskOnResident(std::function<void()> &&task);
    virtual bool PostOneShotTask(const std::string &owner, TaskBlockPolicy policy,
        std::function<void()> &&task);

    template <typename Func>
    typename ResidentSyncResult<typename std::invoke_result<Func>::type>::type RunTaskOnResidentSync(Func &&func,
        uint32_t timeoutSec = MAX_RESIDENT_SYNC_TIMEOUT_SEC)
    {
        using Ret = typename std::invoke_result<Func>::type;
        if constexpr (std::is_void_v<Ret>) {
            return RunOnResidentSyncInner(std::forward<Func>(func), timeoutSec);
        } else {
            auto resultBox = std::make_shared<std::optional<Ret>>(std::nullopt);
            if (resultBox == nullptr) {
                return std::nullopt;
            }
            if (!RunOnResidentSyncInner([func = std::forward<Func>(func), resultBox]() mutable { *resultBox = func(); },
                    timeoutSec)) {
                return std::nullopt;
            }
            return *resultBox;
        }
    }

#ifdef ENABLE_TEST
    virtual void ExecuteAll();
    virtual void EnsureAllTaskExecuted();
#endif // ENABLE_TEST

private:
    // Internal seam behind RunTaskOnResidentSync; test/fake overrides this virtual.
    virtual bool RunOnResidentSyncInner(std::function<void()> &&task, uint32_t timeoutSec);

    std::recursive_mutex mutex_;
    std::map<std::string, std::shared_ptr<TaskRunner>> taskRunnerMap_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#define CHECK_RUNNING_ON_RESIDENT_THREAD()                                                               \
    ::OHOS::UserIam::CompanionDeviceAuth::TaskRunnerManager::GetInstance().CheckRunningOnResidentThread( \
        __PRETTY_FUNCTION__)

#endif // COMPANION_DEVICE_AUTH_TASK_RUNNER_MANAGER_H
