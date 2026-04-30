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

#include "subscription.h"

#include "iam_logger.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_SUBSCRIPTION

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

Subscription::Subscription(CleanupFunc &&cleanup) : cleanup_(std::move(cleanup))
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
}

Subscription::~Subscription()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    Cancel();
}

void Subscription::Cancel()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    auto cleanup = std::move(cleanup_);
    if (cleanup) {
        cleanup();
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
