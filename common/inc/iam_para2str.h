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

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
const int32_t TRUNCATED_WIDTH = 4;
const int SETW_VAL = 2;

std::string GetMaskedString(uint16_t val);
std::string GetTruncatedString(const std::string &val);
std::string GetMaskedString(const std::string &val);
std::string GetTruncatedString(uint16_t val);
std::string GetPointerNullStateString(void *p);
const char *GetBoolStr(bool val);
std::string GetUint8ArrayStr(const std::vector<uint8_t> &val);
void PrintUint8ArrayStr(const char *prefix, const std::vector<uint8_t> &val);

#define GET_MASKED_NUM_STRING(val) GetMaskedString(static_cast<uint16_t>(val))
#define GET_MASKED_NUM_CSTR(val) GET_MASKED_NUM_STRING(val).c_str()
#define GET_MASKED_STR_STRING(val) GetMaskedString(val)
#define GET_MASKED_STR_CSTR(val) GetMaskedString(val).c_str()
#define GET_TRUNCATED_NUM_STR(val) GetTruncatedString(static_cast<uint16_t>(val))
#define GET_TRUNCATED_STRING(val) GetTruncatedString(static_cast<uint16_t>(val))
#define GET_TRUNCATED_CSTR(val) GET_TRUNCATED_STRING(val).c_str()

template <typename T>
std::string GetOptionalString(const std::optional<T> &val)
{
    return val.has_value() ? std::to_string(val.value()) : "nullopt";
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_PARA2STR_H