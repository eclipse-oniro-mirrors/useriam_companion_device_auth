/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "companion_device_auth_driver.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "companion_device_auth_all_in_one_executor.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

CompanionDeviceAuthDriver::CompanionDeviceAuthDriver(
    const std::shared_ptr<CompanionAuthInterfaceAdapter> &companionAuthInterfaceAdapter)
    : companionAuthInterfaceAdapter_(companionAuthInterfaceAdapter)
{
}

void CompanionDeviceAuthDriver::GetExecutorList(std::vector<std::shared_ptr<FwkIAuthExecutorHdi>> &executorList)
{
    IAM_LOGI("start GetExecutorList");
    auto executor = MakeShared<CompanionDeviceAuthAllInOneExecutor>();
    if (executor == nullptr) {
        IAM_LOGE("make shared failed");
        return;
    }
    executorList.push_back(executor);
}

void CompanionDeviceAuthDriver::OnHdiDisconnect()
{
    IAM_LOGI("start");
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
