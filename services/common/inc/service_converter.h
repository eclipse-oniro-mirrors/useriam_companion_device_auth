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

#ifndef COMPANION_DEVICE_AUTH_SERVICE_CONVERTER_H
#define COMPANION_DEVICE_AUTH_SERVICE_CONVERTER_H

#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>

#include "securec.h"

#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

template <typename EnumType, typename UnderlyingType>
class EnumConverter {
public:
    static_assert(std::is_enum<EnumType>::value, "EnumType must be an enum type");
    static_assert(std::is_integral<UnderlyingType>::value, "UnderlyingType must be an integral type");
    static_assert(sizeof(EnumType) == sizeof(UnderlyingType), "EnumType and UnderlyingType must have the same size");

    static UnderlyingType ToUnderlying(const EnumType &value)
    {
        return static_cast<UnderlyingType>(value);
    }

    static EnumType FromUnderlying(const UnderlyingType &value)
    {
        return static_cast<EnumType>(value);
    }

    static std::vector<UnderlyingType> ToUnderlyingVec(const std::vector<EnumType> &enumVec)
    {
        std::vector<UnderlyingType> result;
        result.reserve(enumVec.size());
        for (const auto &value : enumVec) {
            result.push_back(ToUnderlying(value));
        }
        return result;
    }

    static std::vector<EnumType> FromUnderlyingVec(const std::vector<UnderlyingType> &underlyingVec)
    {
        std::vector<EnumType> result;
        result.reserve(underlyingVec.size());
        for (const auto &value : underlyingVec) {
            result.push_back(FromUnderlying(value));
        }
        return result;
    }
};

using ProtocolIdConverter = EnumConverter<ProtocolId, uint16_t>;
using CapabilityConverter = EnumConverter<Capability, uint16_t>;
using SecureProtocolIdConverter = EnumConverter<SecureProtocolId, uint16_t>;

inline std::vector<uint8_t> ConvertUint64ToUint8Vec(uint64_t value)
{
    std::vector<uint8_t> bytes(sizeof(uint64_t));
    if (!bytes.empty() && memcpy_s(bytes.data(), bytes.size(), &value, sizeof(uint64_t)) != EOK) {
        return {};
    }
    return bytes;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SERVICE_CONVERTER_H
