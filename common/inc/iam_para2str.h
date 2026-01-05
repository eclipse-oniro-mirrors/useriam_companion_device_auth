/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef IAM_PARA2STR_H
#define IAM_PARA2STR_H

#include <iomanip>
#include <map>
#include <optional>
#include <sstream>
#include <string>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using namespace std;
const int32_t TRUNCATED_WIDTH = 4;
const int SETW_VAL = 2;
static inline std::string GetMaskedString(uint16_t val)
{
    std::ostringstream ss;
    ss << "0xXXXX" << std::setfill('0') << std::setw(TRUNCATED_WIDTH) << std::hex << val;
    return ss.str();
}

#define GET_MASKED_NUM_STRING(val) GetMaskedString(static_cast<uint16_t>(val))
#define GET_MASKED_NUM_CSTR(val) GET_MASKED_NUM_STRING(val).c_str()
#define GET_MASKED_STR_STRING(val) GetMaskedString(val)
#define GET_MASKED_STR_CSTR(val) GetMaskedString(val).c_str()

static inline std::string GetTruncatedString(const std::string &val)
{
    constexpr size_t tailVisibleLen = 4;
    if (val.empty()) {
        return std::string(tailVisibleLen, '0');
    }
    if (val.size() <= tailVisibleLen) {
        if (val.size() == tailVisibleLen) {
            return val;
        }
        return std::string(tailVisibleLen - val.size(), '0') + val;
    }
    std::string tail = val.substr(val.size() - tailVisibleLen);
    return tail;
}

static inline std::string GetMaskedString(const std::string &val)
{
    constexpr size_t maskedLen = 4;
    return std::string(maskedLen, '*') + GetTruncatedString(val);
}

static inline std::string GetTruncatedString(uint32_t val)
{
    std::ostringstream ss;
    ss << std::setfill('0') << std::setw(TRUNCATED_WIDTH) << std::hex << val;
    return ss.str();
}

#define GET_TRUNCATED_STRING(val) GetTruncatedString(static_cast<uint16_t>(val))
#define GET_TRUNCATED_CSTR(val) GET_TRUNCATED_STRING(val).c_str()

static inline std::string GetPointerNullStateString(void *p)
{
    return p == nullptr ? "null" : "non-null";
}

static inline const char *GetBoolStr(bool val)
{
    return val ? "true" : "false";
}

template <typename T>
static inline std::string GetOptionalString(const std::optional<T> &val)
{
    return val.has_value() ? std::to_string(val.value()) : "nullopt";
}

static inline std::string GetUint8ArrayStr(const std::vector<uint8_t> &val)
{
    std::ostringstream ss;
    ss << "[";
    for (size_t i = 0; i < val.size(); ++i) {
        if (i > 0) {
            ss << ", ";
        }
        ss << "0x" << std::setfill('0') << std::setw(SETW_VAL) << std::hex << static_cast<uint32_t>(val[i]);
    }
    ss << "]";
    return ss.str();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_PARA2STR_H