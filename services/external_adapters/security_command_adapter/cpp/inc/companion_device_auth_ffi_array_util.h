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

#ifndef COMPANION_DEVICE_AUTH_FFI_ARRAY_UTIL_H
#define COMPANION_DEVICE_AUTH_FFI_ARRAY_UTIL_H

#include <cstdint>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

#include "securec.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "iam_safe_arithmetic.h"

#include "companion_device_auth_ffi_types.h"

#ifndef LOG_TAG
#define LOG_TAG "CDA_SA"
#endif
#ifndef LOG_FILE_ID
#define LOG_FILE_ID LOG_FILE_CDA_FFI_ARRAY_UTIL
#endif

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

template <typename T, size_t N>
bool FixedArrayToVector(const T (&arr)[N], std::vector<T> &vec)
{
    vec.assign(arr, arr + N);
    return true;
}

template <typename T, size_t N>
bool VectorToFixedArray(const std::vector<T> &vec, T (&arr)[N], const char *name)
{
    if (vec.size() != N) {
        IAM_LOGE("Vector size mismatch for %{public}s: %{public}zu != %{public}zu", name, vec.size(), N);
        return false;
    }
    auto copySizeOpt = SafeMul(N, sizeof(T));
    ENSURE_OR_RETURN_VAL(copySizeOpt.has_value(), false);

    if (memcpy_s(arr, sizeof(arr), vec.data(), copySizeOpt.value()) != EOK) {
        IAM_LOGE("Failed to copy %{public}s", name);
        return false;
    }
    return true;
}

template <typename FfiArrayType, typename T>
bool FfiArrayToVector(const FfiArrayType &ffiArr, std::vector<T> &vec)
{
    constexpr size_t maxSize = sizeof(ffiArr.data) / sizeof(ffiArr.data[0]);
    if (ffiArr.len > maxSize) {
        IAM_LOGE("FFI array length exceeds maximum: %{public}u > %{public}zu", ffiArr.len, maxSize);
        return false;
    }

    using ElementType = typename std::remove_reference<decltype(ffiArr.data[0])>::type;

    if constexpr (std::is_same_v<T, uint8_t>) {
        vec.assign(ffiArr.data, ffiArr.data + ffiArr.len);
    } else {
        static_assert(sizeof(T) == sizeof(ElementType),
            "Type size mismatch: FFI array element type and target vector element type must have the same size");

        vec.clear();
        if (ffiArr.len > 0) {
            try {
                vec.reserve(ffiArr.len);
            } catch (...) {
                IAM_LOGE("Failed to reserve memory for vector conversion");
                return false;
            }
            for (uint32_t i = 0; i < ffiArr.len; ++i) {
                vec.push_back(static_cast<T>(ffiArr.data[i]));
            }
        }
    }
    return true;
}

template <typename FfiArrayType, typename T>
bool VectorToFfiArray(const std::vector<T> &vec, FfiArrayType &ffiArr, const char *name)
{
    constexpr size_t maxSize = sizeof(ffiArr.data) / sizeof(ffiArr.data[0]);
    if (vec.size() > maxSize) {
        IAM_LOGE("%{public}s size exceeds maximum: %{public}zu > %{public}zu", name, vec.size(), maxSize);
        return false;
    }
    if (vec.size() > UINT32_MAX) {
        IAM_LOGE("%{public}s size exceeds uint32_t maximum: %{public}zu > %{public}u", name, vec.size(), UINT32_MAX);
        return false;
    }
    ffiArr.len = static_cast<uint32_t>(vec.size());

    using ElementType = typename std::remove_reference<decltype(ffiArr.data[0])>::type;
    if constexpr (std::is_same_v<T, ElementType> && (std::is_integral_v<T> || std::is_enum_v<T>)) {
        if (ffiArr.len > 0) {
            auto copySizeOpt = SafeMul(ffiArr.len, static_cast<uint32_t>(sizeof(ElementType)));
            ENSURE_OR_RETURN_VAL(copySizeOpt.has_value(), false);

            auto bufferSizeOpt = SafeMul(static_cast<uint32_t>(maxSize), static_cast<uint32_t>(sizeof(ElementType)));
            ENSURE_OR_RETURN_VAL(bufferSizeOpt.has_value(), false);

            if (memcpy_s(ffiArr.data, bufferSizeOpt.value(), vec.data(), copySizeOpt.value()) != EOK) {
                IAM_LOGE("Failed to copy %{public}s", name);
                return false;
            }
        }
    } else {
        for (size_t i = 0; i < vec.size(); ++i) {
            ffiArr.data[i] = static_cast<ElementType>(vec[i]);
        }
    }
    return true;
}

template <typename FfiArrayType, typename ItemType, typename ConvertFunc>
bool FfiArrayToVectorWithConvert(const FfiArrayType &ffiArr, std::vector<ItemType> &vec, ConvertFunc convertFunc,
    const char *name)
{
    constexpr size_t maxSize = sizeof(ffiArr.data) / sizeof(ffiArr.data[0]);
    if (ffiArr.len > maxSize) {
        IAM_LOGE("FFI array %{public}s length exceeds maximum: %{public}u > %{public}zu", name, ffiArr.len, maxSize);
        return false;
    }
    vec.clear();
    if (ffiArr.len > 0) {
        try {
            vec.reserve(ffiArr.len);
        } catch (...) {
            IAM_LOGE("Failed to reserve memory for %{public}s conversion", name);
            return false;
        }
        for (uint32_t i = 0; i < ffiArr.len; ++i) {
            ItemType item {};
            if (!convertFunc(ffiArr.data[i], item)) {
                IAM_LOGE("Failed to convert %{public}s at index %{public}u", name, i);
                return false;
            }
            vec.push_back(std::move(item));
        }
    }
    return true;
}

template <typename DataArrayType>
bool DecodeDataArrayToString(const DataArrayType &ffi, std::string &str)
{
    std::vector<uint8_t> vec;
    if (!FfiArrayToVector(ffi, vec)) {
        return false;
    }

    if (vec.empty()) {
        str.clear();
        return true;
    }

    str = std::string(reinterpret_cast<const char *>(vec.data()), vec.size());
    return true;
}

template <typename DataArrayType>
bool EncodeStringToDataArray(const std::string &str, DataArrayType &ffi, const char *name)
{
    std::vector<uint8_t> vec(str.begin(), str.end());
    return VectorToFfiArray(vec, ffi, name);
}

inline bool DecodeMessageArray(const DataArray1024Ffi &ffi, std::vector<uint8_t> &vec)
{
    return FfiArrayToVector(ffi, vec);
}

inline bool EncodeMessageArray(const std::vector<uint8_t> &vec, DataArray1024Ffi &ffi)
{
    return VectorToFfiArray(vec, ffi, "message array");
}

inline bool DecodeMessageArray(const DataArray20000Ffi &ffi, std::vector<uint8_t> &vec)
{
    return FfiArrayToVector(ffi, vec);
}

inline bool EncodeMessageArray(const std::vector<uint8_t> &vec, DataArray20000Ffi &ffi)
{
    return VectorToFfiArray(vec, ffi, "message array");
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#undef LOG_FILE_ID
#undef LOG_TAG
#endif // COMPANION_DEVICE_AUTH_FFI_ARRAY_UTIL_H
