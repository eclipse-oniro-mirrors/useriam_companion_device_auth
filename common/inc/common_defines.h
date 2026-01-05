/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_COMMON_H
#define COMPANION_DEVICE_AUTH_COMMON_H

#include <cstdbool>
#include <cstdint>
#include <map>
#include <string>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
constexpr int32_t COMPANION_DEVICE_AUTH_SA_ID = 945;
enum ResultCode : int32_t {
    SUCCESS = 0,
    FAIL = 1,
    GENERAL_ERROR = 2,
    CANCELED = 3,
    TIMEOUT = 4,
    TYPE_NOT_SUPPORT = 5,
    TRUST_LEVEL_NOT_SUPPORT = 6,
    BUSY = 7,
    INVALID_PARAMETERS = 8,
    LOCKED = 9,
    NOT_ENROLLED = 10,
    CANCELED_FROM_WIDGET = 11,
    HARDWARE_NOT_SUPPORTED = 12,
    PIN_EXPIRED = 13,
    COMPLEXITY_CHECK_FAILED = 14,
    AUTH_TOKEN_CHECK_FAILED = 15,
    AUTH_TOKEN_EXPIRED = 16,
    COMMUNICATION_ERROR = 17,

    CHECK_PERMISSION_FAILED = 20001,
    CHECK_SYSTEM_PERMISSION_FAILED = 20002,
    INVALID_BUSINESS_ID = 20003,
    USER_ID_NOT_FOUND = 20004,
};

enum class DeviceIdType : int32_t {
    UNKNOWN = 0,
    UNIFIED_DEVICE_ID = 1,
    VENDOR_BEGIN = 10000,
};

enum class SelectPurpose : int32_t {
    SELECT_ADD_DEVICE = 1,
    SELECT_AUTH_DEVICE = 2,
    CHECK_OPERATION_INTENT = 3,
    VENDOR_BEGIN = 10000,
};

enum class AuthType : int32_t {
    PIN = 1,
    FACE = 2,
    FINGERPRINT = 4,
    COMPANION_DEVICE = 64,
};

enum class BusinessId : int32_t {
    INVALID = 0,
    DEFAULT = 1,
    VENDOR_BEGIN = 10000,
};

constexpr size_t ARGS_ONE = 1;
constexpr size_t ARGS_TWO = 2;

constexpr size_t PARAM0 = 0;
constexpr size_t PARAM1 = 1;

const uint64_t TOKEN_ID_LOW_MASK = 0xffffffff;
const int32_t FRAMEWORKS_CHECK_PERMISSION_FAILED = 201;
const int32_t FRAMEWORKS_CHECK_SYSTEM_PERMISSION_FAILED = 202;
const int32_t FRAMEWORKS_GENERAL_ERROR = 32600001;
const int32_t FRAMEWORKS_NOT_FOUND = 32600002;
const int32_t FRAMEWORKS_INVALID_PARAMS = 32600003;
const std::string USE_USER_IDM_PERMISSION = "ohos.permission.USE_USER_IDM";
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMMON_H
