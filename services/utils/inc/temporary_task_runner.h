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

#ifndef COMPANION_DEVICE_AUTH_TEMPORARY_TASK_RUNNER_H
#define COMPANION_DEVICE_AUTH_TEMPORARY_TASK_RUNNER_H

#include <mutex>
#include <string>

#include "nocopyable.h"
#include "thread_pool.h"

#include "task_runner.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class TemporaryTaskRunner : public TaskRunner, NoCopyable {
public:
    TemporaryTaskRunner(std::string name, bool canSuspend);
    ~TemporaryTaskRunner() override;
    void PostTask(Task &&task) override;
    void Suspend() override;

private:
    OHOS::ThreadPool pool_;
    bool canSuspend_ = false;

    std::recursive_mutex mutex_;
    bool isSuspended_ = false;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEMPORARY_TASK_RUNNER_H
