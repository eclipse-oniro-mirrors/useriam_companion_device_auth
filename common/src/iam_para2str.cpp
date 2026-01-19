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

#include "iam_para2str.h"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "iam_logger.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

#define LOG_TAG "CDA_COMM"

std::string GetMaskedString(uint16_t val)
{
    std::ostringstream ss;
    ss << "0xXXXX" << std::setfill('0') << std::setw(TRUNCATED_WIDTH) << std::hex << val;
    return ss.str();
}

std::string GetTruncatedString(const std::string &val)
{
    constexpr char macSeparator = ':';
    constexpr uint32_t macLen = 17;
    constexpr size_t macSeparatorCount = 5;
    constexpr size_t macSegmentLen = 2;
    constexpr size_t tailVisibleLen = 4;

    if (val.size() == macLen && std::count(val.begin(), val.end(), macSeparator) == macSeparatorCount) {
        return val.substr(0, macSegmentLen) + val.substr(macLen - macSegmentLen);
    }

    if (val.empty()) {
        return std::string(tailVisibleLen, '0');
    }

    if (val.size() == tailVisibleLen) {
        return val;
    }

    if (val.size() < tailVisibleLen) {
        return std::string(tailVisibleLen - val.size(), '0') + val;
    }
    std::string tail = val.substr(val.size() - tailVisibleLen);
    return tail;
}

std::string GetMaskedString(const std::string &val)
{
    constexpr size_t maskedLen = 4;
    return std::string(maskedLen, '*') + GetTruncatedString(val);
}

std::string GetTruncatedString(uint32_t val)
{
    std::ostringstream ss;
    ss << std::setfill('0') << std::setw(TRUNCATED_WIDTH) << std::hex << val;
    return ss.str();
}

std::string GetPointerNullStateString(void *p)
{
    return p == nullptr ? "null" : "non-null";
}

const char *GetBoolStr(bool val)
{
    return val ? "true" : "false";
}

std::string GetUint8ArrayStr(const std::vector<uint8_t> &val)
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

static std::vector<std::string_view> SplitStringByLength(std::string_view str, size_t chunkSize)
{
    std::vector<std::string_view> chunks;

    for (size_t i = 0; i < str.length(); i += chunkSize) {
        chunks.push_back(str.substr(i, chunkSize));
    }

    return chunks;
}

void PrintUint8ArrayStr(const char *prefix, const std::vector<uint8_t> &val)
{
    if (prefix == nullptr) {
        prefix = "";
    }

    constexpr size_t maxLogLength = 3900;
    std::string arrayStr = GetUint8ArrayStr(val);
    if (arrayStr.length() <= maxLogLength) {
        IAM_LOGI("%{public}s%{public}s", prefix, arrayStr.c_str());
        return;
    }

    std::vector<std::string_view> chunks = SplitStringByLength(arrayStr, maxLogLength);
    for (size_t i = 0; i < chunks.size(); ++i) {
        std::string chunkStr(chunks[i]);
        IAM_LOGI("%{public}s[part %{public}zu]%{public}s", prefix, i, chunkStr.c_str());
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
