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

#ifndef CDA_SECURE_VECTOR_H
#define CDA_SECURE_VECTOR_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SecureVector {
public:
    SecureVector() = default;
    template <class It>
    SecureVector(It first, It last) : data_(first, last)
    {
    }
    explicit SecureVector(std::vector<uint8_t> &&other) noexcept : data_(std::move(other))
    {
    }
    explicit SecureVector(const std::vector<uint8_t> &other) : data_(other)
    {
    }
    ~SecureVector()
    {
        Clear();
    }

    SecureVector(const SecureVector &) = delete;
    SecureVector &operator=(const SecureVector &) = delete;
    SecureVector(SecureVector &&) noexcept = default; // moved-from data_ is empty -> dtor Clear() is a no-op
    SecureVector &operator=(SecureVector &&other) noexcept
    {
        if (this != &other) {
            Clear();
            data_ = std::move(other.data_);
        }
        return *this;
    }

    const std::vector<uint8_t> &Get() const
    {
        return data_;
    }

    void Clear()
    {
        if (!data_.empty()) {
            (void)memset_s(data_.data(), data_.size(), 0, data_.size());
        }
        data_.clear();
    }

private:
    std::vector<uint8_t> data_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // CDA_SECURE_VECTOR_H
