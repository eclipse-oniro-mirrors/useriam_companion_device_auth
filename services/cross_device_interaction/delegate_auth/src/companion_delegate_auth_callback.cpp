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

#include "companion_delegate_auth_callback.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "cda_attributes.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionDelegateAuthCallback::CompanionDelegateAuthCallback(ResultCallback &&callback) : callback_(std::move(callback))
{
}

void CompanionDelegateAuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo,
    const UserAuth::Attributes &extraInfo)
{
    IAM_LOGI("module=%{public}d acquireInfo=%{public}u", module, acquireInfo);
}

void CompanionDelegateAuthCallback::OnResult(int32_t result, const UserAuth::Attributes &extraInfo)
{
    IAM_LOGI("result=%{public}d", result);
    std::vector<uint8_t> data = extraInfo.Serialize();
    TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this(), result, data]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->HandleResult(result, data);
    });
}

void CompanionDelegateAuthCallback::HandleResult(int32_t result, const std::vector<uint8_t> &data)
{
    IAM_LOGI("result=%{public}d", result);
    if (!callback_) {
        return;
    }
    auto callback = std::move(callback_);
    callback(static_cast<ResultCode>(result), data);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
