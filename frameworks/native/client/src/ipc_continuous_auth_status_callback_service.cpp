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

#include "ipc_continuous_auth_status_callback_service.h"

#include <memory>

#include "iam_check.h"
#include "iam_logger.h"

#include "common_defines.h"
#include "companion_device_auth_common_defines.h"

#define LOG_TAG "CDA_SDK"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
IpcContinuousAuthStatusCallbackService::IpcContinuousAuthStatusCallbackService(int32_t userId,
    std::optional<uint64_t> templateId, const std::shared_ptr<IContinuousAuthStatusCallback> &impl)
    : userId_(userId),
      templateId_(templateId),
      callback_(impl)
{
}

int32_t IpcContinuousAuthStatusCallbackService::OnContinuousAuthStatusChange(const IpcContinuousAuthStatus &status)
{
    IAM_LOGI("start, isAuthPassed:%{public}d, hasAuthTrustLevel:%{public}d, authTrustLevel:%{public}d",
        status.isAuthPassed, status.hasAuthTrustLevel, status.authTrustLevel);
    ENSURE_OR_RETURN_VAL(callback_ != nullptr, GENERAL_ERROR);
    if (!status.hasAuthTrustLevel) {
        callback_->OnContinuousAuthStatusChange(status.isAuthPassed);
        return SUCCESS;
    }

    callback_->OnContinuousAuthStatusChange(status.isAuthPassed, status.authTrustLevel);
    return SUCCESS;
}

int32_t IpcContinuousAuthStatusCallbackService::GetUserId()
{
    return userId_;
}

std::optional<uint64_t> IpcContinuousAuthStatusCallbackService::GetTemplateId()
{
    return templateId_;
}

std::shared_ptr<IContinuousAuthStatusCallback> IpcContinuousAuthStatusCallbackService::GetCallback()
{
    return callback_;
}

int32_t IpcContinuousAuthStatusCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t IpcContinuousAuthStatusCallbackService::CallbackExit([[maybe_unused]] uint32_t code,
    [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS