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

#ifndef COMPANION_DEVICE_AUTH_IAM_SAFE_ARITHMETIC_H
#define COMPANION_DEVICE_AUTH_IAM_SAFE_ARITHMETIC_H

#include <optional>
#include <type_traits>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

/**
 * @brief Performs safe addition with overflow detection.
 *
 * @tparam T Integral type (signed or unsigned).
 * @param a First addend.
 * @param b Second addend.
 * @return std::optional<T> Returns the sum if no overflow occurs, otherwise std::nullopt.
 */
template <typename T>
std::optional<T> safe_add(T a, T b)
{
    static_assert(std::is_integral_v<T>, "integral only");
    T result;
    if (__builtin_add_overflow(a, b, &result)) {
        return std::nullopt;
    }
    return result;
}

/**
 * @brief Performs safe subtraction with overflow/underflow detection.
 *
 * @tparam T Integral type (signed or unsigned).
 * @param a Minuend (number to be subtracted from).
 * @param b Subtrahend (number to subtract).
 * @return std::optional<T> Returns the difference if no overflow occurs, otherwise std::nullopt.
 */
template <typename T>
std::optional<T> safe_sub(T a, T b)
{
    static_assert(std::is_integral_v<T>, "integral only");
    T result;
    if (__builtin_sub_overflow(a, b, &result)) {
        return std::nullopt;
    }
    return result;
}

/**
 * @brief Performs safe multiplication with overflow detection.
 *
 * @tparam T Integral type (signed or unsigned).
 * @param a Multiplicand.
 * @param b Multiplier.
 * @return std::optional<T> Returns the product if no overflow occurs, otherwise std::nullopt.
 */
template <typename T>
std::optional<T> safe_mul(T a, T b)
{
    static_assert(std::is_integral_v<T>, "integral only");
    T result;
    if (__builtin_mul_overflow(a, b, &result)) {
        return std::nullopt;
    }
    return result;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_IAM_SAFE_ARITHMETIC_H
