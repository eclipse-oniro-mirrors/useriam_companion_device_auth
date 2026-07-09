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

#ifndef FAKE_DATASHARE_RESULT_SET_H
#define FAKE_DATASHARE_RESULT_SET_H

#include "datashare_errno.h"
#include <string>

namespace OHOS {
namespace DataShare {
// Fake result set carrying a single value. An empty value models an absent row (GetRowCount == 0) so
// the "not found" path is exercisable; a non-empty value models one matching row.
class DataShareResultSet {
public:
    DataShareResultSet() = default;
    explicit DataShareResultSet(std::string value) : value_(std::move(value))
    {
    }
    int GetRowCount(int &count)
    {
        count = value_.empty() ? 0 : 1;
        return E_OK;
    }
    int GoToRow(int)
    {
        return E_OK;
    }
    int GetString(int, std::string &value)
    {
        value = value_;
        return E_OK;
    }
    int Close()
    {
        return E_OK;
    }

private:
    std::string value_;
};
} // namespace DataShare
} // namespace OHOS
#endif // FAKE_DATASHARE_RESULT_SET_H
