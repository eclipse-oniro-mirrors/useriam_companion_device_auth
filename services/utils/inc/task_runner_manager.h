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
#include <string>
#include <vector>

#include "task_runner.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

const std::string RESIDENT_TASK_RUNNER_NAME = "ResidentRunner";

class TaskRunnerManager {
public:
    static TaskRunnerManager &GetInstance();

    TaskRunnerManager();
    virtual ~TaskRunnerManager() = default;

    virtual bool RunningOnDefaultTaskRunner() const;
    void SetRunningOnDefaultTaskRunner(bool value);

    // Assert that the current thread is the resident task runner thread.
    // If not, logs a fatal error and aborts the process.
    // This is a design verification check - all business logic must run on the resident thread.
    void AssertRunningOnResidentThread() const;

    virtual bool CreateTaskRunner(const std::string &name);
    virtual void DestroyTaskRunner(const std::string &name);
    virtual void DeleteTaskRunner(const std::string &name);
    virtual std::shared_ptr<TaskRunner> GetTaskRunner(const std::string &name);
    virtual void PostTask(const std::string &name, std::function<void()> &&task);
    virtual void PostTaskOnResident(std::function<void()> &&task);
    virtual void PostTaskOnTemporary(const std::string &name, std::function<void()> &&task);

#ifdef ENABLE_TEST
    virtual void ExecuteAll();
#endif

private:
    std::recursive_mutex mutex_;
    std::map<std::string, std::shared_ptr<TaskRunner>> taskRunnerMap_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TASK_RUNNER_MANAGER_H
