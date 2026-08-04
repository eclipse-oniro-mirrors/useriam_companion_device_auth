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

#include "companion_device_auth_executor_callback.h"

#include <cstdint>
#include <vector>

#include "iam_check.h"
#include "iam_logger.h"

#include "common_defines.h"
#include "result_code_converter.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_CDA_EXECUTOR_CALLBACK

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

CompanionDeviceAuthExecutorCallback::CompanionDeviceAuthExecutorCallback(
    std::shared_ptr<FwkIExecuteCallback> frameworkCallback)
    : frameworkCallback_(frameworkCallback)
{
}

void CompanionDeviceAuthExecutorCallback::operator()(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("received result %{public}d", result);
    FwkResultCode retCode = ToUserAuthResultCode(result);
    ENSURE_OR_RETURN(frameworkCallback_ != nullptr);
    frameworkCallback_->OnResult(retCode, extraInfo);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
