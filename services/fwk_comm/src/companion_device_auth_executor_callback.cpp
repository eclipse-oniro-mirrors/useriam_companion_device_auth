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
#include <map>
#include <vector>

#include "iam_check.h"
#include "iam_logger.h"

#include "common_defines.h"

#define LOG_TAG "CDA_SA"

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
    FwkResultCode retCode = ConvertResultCode(result);
    ENSURE_OR_RETURN(frameworkCallback_ != nullptr);
    frameworkCallback_->OnResult(retCode, extraInfo);
}

FwkResultCode CompanionDeviceAuthExecutorCallback::ConvertResultCode(const ResultCode in)
{
    static const std::map<ResultCode, UserAuth::ResultCode> data = {
        { ResultCode::SUCCESS, UserAuth::ResultCode::SUCCESS },
        { ResultCode::FAIL, UserAuth::ResultCode::FAIL },
        { ResultCode::GENERAL_ERROR, UserAuth::ResultCode::GENERAL_ERROR },
        { ResultCode::CANCELED, UserAuth::ResultCode::CANCELED },
        { ResultCode::TIMEOUT, UserAuth::ResultCode::TIMEOUT },
        { ResultCode::TYPE_NOT_SUPPORT, UserAuth::ResultCode::TYPE_NOT_SUPPORT },
        { ResultCode::TRUST_LEVEL_NOT_SUPPORT, UserAuth::ResultCode::TRUST_LEVEL_NOT_SUPPORT },
        { ResultCode::BUSY, UserAuth::ResultCode::BUSY },
        { ResultCode::INVALID_PARAMETERS, UserAuth::ResultCode::INVALID_PARAMETERS },
        { ResultCode::LOCKED, UserAuth::ResultCode::LOCKED },
        { ResultCode::NOT_ENROLLED, UserAuth::ResultCode::NOT_ENROLLED },
        { ResultCode::CANCELED_FROM_WIDGET, UserAuth::ResultCode::CANCELED_FROM_WIDGET },
        { ResultCode::HARDWARE_NOT_SUPPORTED, UserAuth::ResultCode::HARDWARE_NOT_SUPPORTED },
        { ResultCode::PIN_EXPIRED, UserAuth::ResultCode::PIN_EXPIRED },
        { ResultCode::COMPLEXITY_CHECK_FAILED, UserAuth::ResultCode::COMPLEXITY_CHECK_FAILED },
        { ResultCode::AUTH_TOKEN_CHECK_FAILED, UserAuth::ResultCode::AUTH_TOKEN_CHECK_FAILED },
        { ResultCode::AUTH_TOKEN_EXPIRED, UserAuth::ResultCode::AUTH_TOKEN_EXPIRED },
        { ResultCode::COMMUNICATION_ERROR, UserAuth::ResultCode::FAIL },
        { ResultCode::NO_VALID_CREDENTIAL, UserAuth::ResultCode::NO_VALID_CREDENTIAL },
    };

    UserAuth::ResultCode out;
    auto iter = data.find(in);
    if (iter == data.end()) {
        out = UserAuth::ResultCode::GENERAL_ERROR;
        IAM_LOGE("convert undefined result code %{public}d to framework result code %{public}d",
            static_cast<int32_t>(in), out);
        return out;
    }
    out = iter->second;
    IAM_LOGI("convert result code %{public}d to framework result code %{public}d", static_cast<int32_t>(in), out);
    return out;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
