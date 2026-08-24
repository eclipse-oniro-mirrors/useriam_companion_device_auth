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

#ifndef COMPANION_DEVICE_AUTH_FRAMEWORK_DEFINES_H
#define COMPANION_DEVICE_AUTH_FRAMEWORK_DEFINES_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

#include "common_defines.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
constexpr size_t UINT64_BYTE_SIZE = 8;
constexpr uint8_t UINT8_BYTE_MASK = 0xFF;
constexpr size_t MAX_ARRAY_LENGTH = 20 * 1024;
constexpr int MAX_STRING_LENGTH = 65536;
constexpr int32_t ATL1 = 10000;
constexpr int32_t ATL2 = 20000;
constexpr int32_t ATL3 = 30000;
constexpr int32_t ATL4 = 40000;

inline const std::map<int32_t, std::string> g_result2Str = {
    { static_cast<int32_t>(ResultCode::GENERAL_ERROR),
        "The system service is not working properly. Please try again later." },
    { static_cast<int32_t>(ResultCode::NOT_ENROLLED), "The template is not found." },
    { static_cast<int32_t>(ResultCode::USER_ID_NOT_FOUND), "The local user is not found." },
    { static_cast<int32_t>(ResultCode::INVALID_BUSINESS_ID), "The business id is invalid." },
    { static_cast<int32_t>(ResultCode::CHECK_PERMISSION_FAILED), "Permission denied." },
    { static_cast<int32_t>(ResultCode::CHECK_SYSTEM_PERMISSION_FAILED), "Not system application." }
};

inline const std::string &GetResultMsg(int32_t error)
{
    auto it = g_result2Str.find(error);
    if (it != g_result2Str.end()) {
        return it->second;
    }
    return g_result2Str.at(GENERAL_ERROR);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FRAMEWORK_DEFINES_H
