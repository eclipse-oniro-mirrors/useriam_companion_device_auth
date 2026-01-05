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

#include "resident_task_runner.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <utility>

#include "nocopyable.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "relative_timer.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
std::once_flag g_initFlag;
} // namespace

ResidentTaskRunner::ResidentTaskRunner() = default;

void ResidentTaskRunner::PostTask(Task &&task)
{
    std::call_once(g_initFlag, []() {
        RelativeTimer::GetInstance().PostTask(
            []() { TaskRunnerManager::GetInstance().SetRunningOnDefaultTaskRunner(true); }, 0);
    });

    RelativeTimer::GetInstance().PostTask(std::move(task), 0);
}

void ResidentTaskRunner::Suspend()
{
    IAM_LOGE("can not suspend");
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
