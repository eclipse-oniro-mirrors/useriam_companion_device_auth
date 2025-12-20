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
// System ability id for CompanionDeviceAuth service
constexpr int32_t COMPANION_DEVICE_AUTH_SA_ID = 945;
enum ResultCode : int32_t {
    /** The result is success. */
    SUCCESS = 0,
    /** Compile fail. */
    FAIL = 1,
    /** The result is fail, because an unknown error occurred. */
    GENERAL_ERROR = 2,
    /** The result is fail, because the request was canceled. */
    CANCELED = 3,
    /** The result is fail ,because of time out. */
    TIMEOUT = 4,
    /** The result is fail ,because type is not support. */
    TYPE_NOT_SUPPORT = 5,
    /** The result is fail ,because trust level is not support. */
    TRUST_LEVEL_NOT_SUPPORT = 6,
    /** The result is fail, because the service was busy. */
    BUSY = 7,
    /** The result is fail, because parameters is invalid. */
    INVALID_PARAMETERS = 8,
    /** The result if fail, because the status is locked. */
    LOCKED = 9,
    /** The result is fail, because the user was not enrolled. */
    NOT_ENROLLED = 10,
    /** The result is fail, because canceled from widget. */
    CANCELED_FROM_WIDGET = 11,
    /** The result is fail, because the hardware is not supported. */
    HARDWARE_NOT_SUPPORTED = 12,
    /** The result is fail, because the pin credential is expired. */
    PIN_EXPIRED = 13,
    /** The result is fail, because the PIN_MIXED does not pass complexity check. */
    COMPLEXITY_CHECK_FAILED = 14,
    /** The result is fail, because the token integrity check failed. */
    AUTH_TOKEN_CHECK_FAILED = 15,
    /** The result is fail, because the token is expired. */
    AUTH_TOKEN_EXPIRED = 16,
    COMMUNICATION_ERROR = 17,
};

enum class SaResultCode : int32_t {
    SUCCESS = 0,
    GENERAL_ERROR = 2,
    INVALID_PARAMETERS = 8,
    CHECK_PERMISSION_FAILED = 201,
    CHECK_SYSTEM_PERMISSION_FAILED = 202,
};

enum class DeviceIdType : int32_t {
    UNKNOWN = 0,
    UNIFIED_DEVICE_ID = 1,
    VENDOR_BEGIN = 10000,
    MAC_ADDRESS = 10001,
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

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMMON_H
