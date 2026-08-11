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

#ifndef COMPANION_DEVICE_AUTH_CDA_JSON_HELPER_H
#define COMPANION_DEVICE_AUTH_CDA_JSON_HELPER_H

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include <nlohmann/json.hpp>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

inline std::optional<nlohmann::json> TryParseJson(const std::string &text)
{
    auto parsed = nlohmann::json::parse(text, nullptr, false);
    if (parsed.is_discarded()) {
        return std::nullopt;
    }
    return parsed;
}

inline std::optional<nlohmann::json> TryParseJson(const std::vector<uint8_t> &bytes)
{
    return TryParseJson(std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size()));
}

template <typename T, std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool>, int> = 0>
bool GetJsonField(const nlohmann::json &obj, const char *key, T &out)
{
    auto it = obj.find(key);
    if (it == obj.end()) {
        return false;
    }
    const auto &value = *it;
    if constexpr (std::is_signed_v<T>) {
        if (!value.is_number_integer()) {
            return false;
        }
        if (value.is_number_unsigned()) {
            uint64_t raw = value.get<uint64_t>();
            if (raw > static_cast<uint64_t>(std::numeric_limits<T>::max())) {
                return false;
            }
            out = static_cast<T>(raw);
        } else {
            int64_t raw = value.get<int64_t>();
            if (raw < static_cast<int64_t>(std::numeric_limits<T>::min())) {
                return false;
            }
            out = static_cast<T>(raw);
        }
    } else {
        if (!value.is_number_unsigned()) {
            return false;
        }
        uint64_t raw = value.get<uint64_t>();
        if (raw > static_cast<uint64_t>(std::numeric_limits<T>::max())) {
            return false;
        }
        out = static_cast<T>(raw);
    }
    return true;
}

inline bool GetJsonField(const nlohmann::json &obj, const char *key, std::string &out, size_t maxLen)
{
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_string()) {
        return false;
    }
    const auto &value = it->get_ref<const std::string &>();
    if (value.size() > maxLen) {
        return false;
    }
    out = value;
    return true;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_CDA_JSON_HELPER_H