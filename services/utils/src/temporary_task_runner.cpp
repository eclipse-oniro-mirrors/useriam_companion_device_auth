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

#include <atomic>
#include <cstdint>
#include <memory>
#include <utility>

#include "nocopyable.h"

#include "iam_logger.h"

#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_TEMPORARY_TASK_RUNNER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
std::string BuildThreadName()
{
    static std::atomic<uint32_t> serial = 0;
    return "cda_" + std::to_string(serial.fetch_add(1));
}
} // namespace

TemporaryTaskRunner::TemporaryTaskRunner(std::string name, std::string owner, TaskBlockPolicy policy)
    : pool_(BuildThreadName()), policy_(policy), owner_(std::move(owner))
{
    pool_.Start(1);
}

TemporaryTaskRunner::~TemporaryTaskRunner()
{
    pool_.Stop();
}

TaskBlockPolicy TemporaryTaskRunner::GetBlockPolicy() const
{
    return policy_;
}

std::string TemporaryTaskRunner::GetOwner() const
{
    return owner_;
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
    isSuspended_ = true;
}

std::shared_ptr<TaskRunner> TaskRunner::GetDefaultRunner()
{
    return TaskRunnerManager::GetInstance().GetTaskRunner(RESIDENT_TASK_RUNNER_NAME);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
