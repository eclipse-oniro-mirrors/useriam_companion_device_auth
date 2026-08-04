/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_RESULT_CODE_CONVERTER_H
#define COMPANION_DEVICE_AUTH_RESULT_CODE_CONVERTER_H

#include <cstdint>

#include "common_defines.h"
#include "iam_common_defines.h"
#include "iam_logger.h"

#ifndef LOG_TAG
#define LOG_TAG "CDA_SA"
#endif
#ifndef LOG_FILE_ID
#define LOG_FILE_ID LOG_FILE_RESULT_CODE_CONVERTER
#endif

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Single source of truth for CDA ResultCode <-> UserAuth::ResultCode.
// COMMUNICATION_ERROR is CDA-only: it collapses to FAIL one-way (UserAuth never reports it),
// so reverse lookup of FAIL must hit the FAIL row below — keep it before COMMUNICATION_ERROR.
struct ResultCodeMapping {
    ResultCode cdaCode;
    UserAuth::ResultCode userAuthCode;
};

constexpr ResultCodeMapping RESULT_CODE_MAPPINGS[] = {
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
    { ResultCode::NO_VALID_CREDENTIAL, UserAuth::ResultCode::NO_VALID_CREDENTIAL },
    { ResultCode::COMMUNICATION_ERROR, UserAuth::ResultCode::FAIL },
};

inline UserAuth::ResultCode ToUserAuthResultCode(ResultCode in)
{
    for (const auto &m : RESULT_CODE_MAPPINGS) {
        if (m.cdaCode == in) {
            return m.userAuthCode;
        }
    }
    IAM_LOGE("ToUserAuthResultCode: unmapped cda code %{public}d, fallback to GENERAL_ERROR", static_cast<int32_t>(in));
    return UserAuth::ResultCode::GENERAL_ERROR;
}

inline ResultCode FromUserAuthResultCode(int32_t in)
{
    auto userAuthCode = static_cast<UserAuth::ResultCode>(in);
    for (const auto &m : RESULT_CODE_MAPPINGS) {
        if (m.userAuthCode == userAuthCode) {
            return m.cdaCode;
        }
    }
    IAM_LOGE("FromUserAuthResultCode: unmapped userauth code %{public}d, fallback to GENERAL_ERROR", in);
    return ResultCode::GENERAL_ERROR;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#undef LOG_FILE_ID
#undef LOG_TAG
#endif // COMPANION_DEVICE_AUTH_RESULT_CODE_CONVERTER_H
