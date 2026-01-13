/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "temporary_task_runner.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "nocopyable.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

TemporaryTaskRunner::TemporaryTaskRunner(std::string name, bool canSuspend) : pool_(name), canSuspend_(canSuspend)
{
    pool_.Start(1);
}

TemporaryTaskRunner::~TemporaryTaskRunner()
{
    pool_.Stop();
}

void TemporaryTaskRunner::PostTask(Task &&task)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isSuspended_) {
        IAM_LOGE("is suspended");
        return;
    }
    pool_.AddTask(std::move(task));
}

void TemporaryTaskRunner::Suspend()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!canSuspend_) {
        IAM_LOGE("can not suspend");
        return;
    }
    isSuspended_ = true;
}

std::shared_ptr<TaskRunner> TaskRunner::GetDefaultRunner()
{
    return TaskRunnerManager::GetInstance().GetTaskRunner(RESIDENT_TASK_RUNNER_NAME);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
