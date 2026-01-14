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

#include <limits>
#include <optional>
#include <type_traits>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

/**
 * @brief Performs safe addition with overflow detection for unsigned integers.
 *
 * @tparam T Unsigned integral type (uint8_t, uint16_t, uint32_t, uint64_t, size_t, etc.).
 * @param a First addend.
 * @param b Second addend.
 * @return std::optional<T> Returns the sum if no overflow occurs, otherwise std::nullopt.
 *
 * @note This function only supports unsigned integer types to ensure type consistency.
 *       Both parameters must be of the same unsigned type.
 */
template <typename T>
typename std::enable_if<std::is_unsigned_v<T>, std::optional<T>>::type safe_add(T a, T b)
{
    if (a > std::numeric_limits<T>::max() - b) {
        return std::nullopt;
    }
    return a + b;
}

/**
 * @brief Performs safe multiplication with overflow detection for unsigned integers.
 *
 * @tparam T Unsigned integral type (uint8_t, uint16_t, uint32_t, uint64_t, size_t, etc.).
 * @param a Multiplicand.
 * @param b Multiplier.
 * @return std::optional<T> Returns the product if no overflow occurs, otherwise std::nullopt.
 *
 * @note This function only supports unsigned integer types to ensure type consistency.
 *       Both parameters must be of the same unsigned type.
 */
template <typename T>
typename std::enable_if<std::is_unsigned_v<T>, std::optional<T>>::type safe_multiply(T a, T b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    if (a > std::numeric_limits<T>::max() / b) {
        return std::nullopt;
    }
    return a * b;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_IAM_SAFE_ARITHMETIC_H
