/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "cda_attributes.h"

#include <cstring>

#include "securec.h"
#include <endian.h>

#include "iam_logger.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace {
template <typename T>
struct EncodingTraits;

template <>
struct EncodingTraits<uint64_t> {
    static constexpr size_t size = sizeof(uint64_t);
    static uint64_t toLE(uint64_t value)
    {
        return htole64(value);
    }
    static uint64_t fromLE(uint64_t value)
    {
        return le64toh(value);
    }
};

template <>
struct EncodingTraits<uint32_t> {
    static constexpr size_t size = sizeof(uint32_t);
    static uint32_t toLE(uint32_t value)
    {
        return htole32(value);
    }
    static uint32_t fromLE(uint32_t value)
    {
        return le32toh(value);
    }
};

template <>
struct EncodingTraits<uint16_t> {
    static constexpr size_t size = sizeof(uint16_t);
    static uint16_t toLE(uint16_t value)
    {
        return htole16(value);
    }
    static uint16_t fromLE(uint16_t value)
    {
        return le16toh(value);
    }
};

template <>
struct EncodingTraits<uint8_t> {
    static constexpr size_t size = sizeof(uint8_t);
    static uint8_t toLE(uint8_t value)
    {
        return value;
    }
    static uint8_t fromLE(uint8_t value)
    {
        return value;
    }
};

template <>
struct EncodingTraits<int64_t> {
    static constexpr size_t size = sizeof(int64_t);
    static uint64_t toLE(int64_t value)
    {
        return htole64(static_cast<uint64_t>(value));
    }
    static int64_t fromLE(uint64_t value)
    {
        return static_cast<int64_t>(le64toh(value));
    }
};

template <>
struct EncodingTraits<int32_t> {
    static constexpr size_t size = sizeof(int32_t);
    static uint32_t toLE(int32_t value)
    {
        return htole32(static_cast<uint32_t>(value));
    }
    static int32_t fromLE(uint32_t value)
    {
        return static_cast<int32_t>(le32toh(value));
    }
};

template <>
struct EncodingTraits<Attributes::AttributeKey> {
    static uint32_t toLE(Attributes::AttributeKey value)
    {
        return htole32(static_cast<uint32_t>(value));
    }
    static Attributes::AttributeKey fromLE(uint32_t value)
    {
        return static_cast<Attributes::AttributeKey>(le32toh(value));
    }
};

template <typename T>
bool EncodeNumericValue(const T &src, std::vector<uint8_t> &dst)
{
    using Traits = EncodingTraits<T>;
    auto srcLE = Traits::toLE(src);
    const uint8_t *srcPtr = reinterpret_cast<const uint8_t *>(&srcLE);
    dst.assign(srcPtr, srcPtr + sizeof(srcLE));
    return true;
}

template <typename T>
bool DecodeNumericValue(const std::vector<uint8_t> &src, T &dst)
{
    using Traits = EncodingTraits<T>;
    if (src.size() != Traits::size) {
        IAM_LOGE("DecodeNumericValue size mismatch, expected: %{public}zu, actual: %{public}zu", Traits::size,
            src.size());
        return false;
    }
    decltype(Traits::toLE(dst)) dstLE;
    if (memcpy_s(&dstLE, sizeof(dstLE), src.data(), src.size()) != EOK) {
        IAM_LOGE("DecodeNumericValue memcpy_s failed, size: %{public}zu", src.size());
        return false;
    }
    dst = Traits::fromLE(dstLE);
    return true;
}

template <typename T>
bool EncodeNumericArrayValue(const std::vector<T> &src, std::vector<uint8_t> &dst)
{
    using Traits = EncodingTraits<T>;
    auto outSize = src.size() * Traits::size;

    std::vector<uint8_t> out(outSize);
    using LEType = decltype(Traits::toLE(T()));

    LEType *outPtr = reinterpret_cast<LEType *>(out.data());
    for (size_t i = 0; i < src.size(); i++) {
        outPtr[i] = Traits::toLE(src[i]);
    }

    dst = std::move(out);
    return true;
}

template <typename T>
bool DecodeNumericArrayValue(const std::vector<uint8_t> &src, std::vector<T> &dst)
{
    using Traits = EncodingTraits<T>;
    if (src.size() % Traits::size != 0) {
        IAM_LOGE("DecodeNumericArrayValue size not multiple of element size, src.size: %{public}zu, element_size: "
                 "%{public}zu",
            src.size(), Traits::size);
        return false;
    }

    using LEType = decltype(Traits::toLE(T()));
    size_t count = src.size() / Traits::size;
    std::vector<T> out(count);

    for (size_t i = 0; i < count; i++) {
        LEType temp;
        if (memcpy_s(&temp, sizeof(temp), src.data() + i * sizeof(LEType), sizeof(LEType)) != EOK) {
            IAM_LOGE("DecodeNumericArrayValue memcpy_s failed at index %{public}zu, element_size: %{public}zu", i,
                sizeof(LEType));
            return false;
        }
        out[i] = Traits::fromLE(temp);
    }

    dst = std::move(out);
    return true;
}
} // namespace

Attributes::Attributes() = default;

Attributes::Attributes(const std::vector<uint8_t> &raw)
{
    constexpr size_t headerSize = sizeof(uint32_t) + sizeof(uint32_t);

    if (raw.empty()) {
        return;
    }

    const uint8_t *curr = raw.data();
    const uint8_t *end = raw.data() + raw.size();
    std::map<AttributeKey, std::vector<uint8_t>> tempMap;

    while (curr < end) {
        size_t remaining = static_cast<size_t>(end - curr);
        if (remaining < headerSize) {
            IAM_LOGE("out of end range, remaining: %{public}zu, need: %{public}zu", remaining, headerSize);
            return;
        }

        uint32_t type;
        if (memcpy_s(&type, sizeof(type), curr, sizeof(uint32_t)) != EOK) {
            IAM_LOGE("memcpy_s failed for type");
            return;
        }
        type = le32toh(type);
        curr += sizeof(uint32_t);
        remaining -= sizeof(uint32_t);

        uint32_t length;
        if (memcpy_s(&length, sizeof(length), curr, sizeof(uint32_t)) != EOK) {
            IAM_LOGE("memcpy_s failed for length");
            return;
        }
        length = le32toh(length);
        curr += sizeof(uint32_t);
        remaining -= sizeof(uint32_t);

        if (length > remaining) {
            IAM_LOGE("check attribute length error, length: %{public}u, remaining: %{public}zu", length, remaining);
            return;
        }

        std::vector<uint8_t> value(curr, curr + length);
        tempMap[static_cast<AttributeKey>(type)] = std::move(value);

        IAM_LOGD("insert_or_assign pair success, type is %{public}u", type);
        curr += length;
    }

    map_ = std::move(tempMap);
}

Attributes::Attributes(const Attributes &other) : map_(other.map_)
{
}

Attributes &Attributes::operator=(const Attributes &other)
{
    if (this != &other) {
        map_ = other.map_;
    }
    return *this;
}

Attributes::Attributes(Attributes &&other) noexcept : map_(std::move(other.map_))
{
}

Attributes &Attributes::operator=(Attributes &&other) noexcept
{
    if (this != &other) {
        map_ = std::move(other.map_);
    }
    return *this;
}

Attributes::~Attributes() = default;

void Attributes::SetBoolValue(AttributeKey key, bool value)
{
    SetUint8Value(key, value ? 1 : 0);
}

void Attributes::SetUint64Value(AttributeKey key, uint64_t value)
{
    std::vector<uint8_t> dest;
    EncodeNumericValue(value, dest);
    map_[key] = std::move(dest);
}

void Attributes::SetUint32Value(AttributeKey key, uint32_t value)
{
    std::vector<uint8_t> dest;
    EncodeNumericValue(value, dest);
    map_[key] = std::move(dest);
}

void Attributes::SetUint16Value(AttributeKey key, uint16_t value)
{
    std::vector<uint8_t> dest;
    EncodeNumericValue(value, dest);
    map_[key] = std::move(dest);
}

void Attributes::SetUint8Value(AttributeKey key, uint8_t value)
{
    std::vector<uint8_t> dest;
    EncodeNumericValue(value, dest);
    map_[key] = std::move(dest);
}

void Attributes::SetInt32Value(AttributeKey key, int32_t value)
{
    std::vector<uint8_t> dest;
    EncodeNumericValue(value, dest);
    map_[key] = std::move(dest);
}

void Attributes::SetInt64Value(AttributeKey key, int64_t value)
{
    std::vector<uint8_t> dest;
    EncodeNumericValue(value, dest);
    map_[key] = std::move(dest);
}

void Attributes::SetStringValue(AttributeKey key, const std::string &value)
{
    std::vector<uint8_t> dest;
    dest.reserve(value.size() + 1);
    dest.assign(value.begin(), value.end());
    dest.push_back(0);
    map_[key] = std::move(dest);
}

void Attributes::SetUint64ArrayValue(AttributeKey key, const std::vector<uint64_t> &value)
{
    std::vector<uint8_t> dest;
    EncodeNumericArrayValue(value, dest);
    map_[key] = std::move(dest);
}

void Attributes::SetUint32ArrayValue(AttributeKey key, const std::vector<uint32_t> &value)
{
    std::vector<uint8_t> dest;
    EncodeNumericArrayValue(value, dest);
    map_[key] = std::move(dest);
}

void Attributes::SetInt32ArrayValue(AttributeKey key, const std::vector<int32_t> &value)
{
    std::vector<uint8_t> dest;
    EncodeNumericArrayValue(value, dest);
    map_[key] = std::move(dest);
}

void Attributes::SetUint16ArrayValue(AttributeKey key, const std::vector<uint16_t> &value)
{
    std::vector<uint8_t> dest;
    EncodeNumericArrayValue(value, dest);
    map_[key] = std::move(dest);
}

void Attributes::SetUint8ArrayValue(AttributeKey key, const std::vector<uint8_t> &value)
{
    map_[key] = value;
}

void Attributes::SetAttributesValue(AttributeKey key, const Attributes &value)
{
    std::vector<uint8_t> dest = value.Serialize();
    if (dest.empty()) {
        IAM_LOGE("Serialize empty");
    }
    map_[key] = std::move(dest);
}

void Attributes::SetAttributesArrayValue(AttributeKey key, const std::vector<Attributes> &array)
{
    std::vector<std::vector<uint8_t>> serializedArray;
    serializedArray.reserve(array.size());

    for (const auto &item : array) {
        serializedArray.push_back(item.Serialize());
    }

    uint32_t dataLen = 0;
    for (const auto &arr : serializedArray) {
        dataLen += (sizeof(uint32_t) + arr.size());
    }

    std::vector<uint8_t> data;
    data.reserve(dataLen);

    for (const auto &arr : serializedArray) {
        uint32_t arrSize = static_cast<uint32_t>(arr.size());
        uint32_t arrSizeLE = htole32(arrSize);
        const uint8_t *sizePtr = reinterpret_cast<const uint8_t *>(&arrSizeLE);
        data.insert(data.end(), sizePtr, sizePtr + sizeof(uint32_t));
        data.insert(data.end(), arr.begin(), arr.end());
    }

    map_[key] = std::move(data);
}

bool Attributes::GetBoolValue(AttributeKey key, bool &value) const
{
    uint8_t u8Value;
    if (!GetUint8Value(key, u8Value)) {
        return false;
    }
    value = (u8Value == 1);
    return true;
}

bool Attributes::GetUint64Value(AttributeKey key, uint64_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    return DecodeNumericValue(iter->second, value);
}

bool Attributes::GetUint32Value(AttributeKey key, uint32_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    return DecodeNumericValue(iter->second, value);
}

bool Attributes::GetUint16Value(AttributeKey key, uint16_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    return DecodeNumericValue(iter->second, value);
}

bool Attributes::GetUint8Value(AttributeKey key, uint8_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    return DecodeNumericValue(iter->second, value);
}

bool Attributes::GetInt32Value(AttributeKey key, int32_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    return DecodeNumericValue(iter->second, value);
}

bool Attributes::GetInt64Value(AttributeKey key, int64_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    return DecodeNumericValue(iter->second, value);
}

bool Attributes::GetStringValue(AttributeKey key, std::string &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    if (iter->second.empty() || iter->second.back() != 0) {
        IAM_LOGE("GetStringValue invalid format, empty: %{public}d, has_null_terminator: %{public}d",
            iter->second.empty(), (!iter->second.empty() && iter->second.back() == 0));
        return false;
    }
    value.assign(iter->second.begin(), iter->second.end() - 1);
    return true;
}

bool Attributes::GetUint64ArrayValue(AttributeKey key, std::vector<uint64_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    return DecodeNumericArrayValue(iter->second, value);
}

bool Attributes::GetUint32ArrayValue(AttributeKey key, std::vector<uint32_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    return DecodeNumericArrayValue(iter->second, value);
}

bool Attributes::GetInt32ArrayValue(AttributeKey key, std::vector<int32_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    return DecodeNumericArrayValue(iter->second, value);
}

bool Attributes::GetUint16ArrayValue(AttributeKey key, std::vector<uint16_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    return DecodeNumericArrayValue(iter->second, value);
}

bool Attributes::GetUint8ArrayValue(AttributeKey key, std::vector<uint8_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    value = iter->second;
    return true;
}

bool Attributes::GetAttributesValue(AttributeKey key, Attributes &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    value = Attributes(iter->second);
    return true;
}

bool Attributes::GetAttributesArrayValue(AttributeKey key, std::vector<Attributes> &array) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    const std::vector<uint8_t> &data = iter->second;
    array.clear();

    uint32_t i = 0;
    while (i < data.size()) {
        if (data.size() - i < sizeof(uint32_t)) {
            IAM_LOGE("GetAttributesArrayValue insufficient data for length, remaining: %{public}zu, need: %{public}zu",
                data.size() - i, sizeof(uint32_t));
            return false;
        }

        uint32_t arrayLenLE;
        if (memcpy_s(&arrayLenLE, sizeof(arrayLenLE), data.data() + i, sizeof(uint32_t)) != EOK) {
            IAM_LOGE("GetAttributesArrayValue memcpy_s failed for array length at offset %{public}u", i);
            return false;
        }
        uint32_t arrayLen = le32toh(arrayLenLE);
        i += sizeof(uint32_t);

        if (data.size() - i < arrayLen) {
            IAM_LOGE("GetAttributesArrayValue insufficient data for array, remaining: %{public}zu, need: %{public}u",
                data.size() - i, arrayLen);
            return false;
        }

        array.emplace_back(std::vector<uint8_t>(data.begin() + i, data.begin() + i + arrayLen));
        i += arrayLen;
    }

    return true;
}

std::vector<uint8_t> Attributes::Serialize() const
{
    uint32_t size = 0;
    for (const auto &[key, value] : map_) {
        size += sizeof(uint32_t) + sizeof(uint32_t) + value.size();
    }

    std::vector<uint8_t> buffer;
    buffer.reserve(size);

    for (const auto &[key, value] : map_) {
        std::vector<uint8_t> type;
        std::vector<uint8_t> length;

        if (!EncodeNumericValue(key, type)) {
            IAM_LOGE("EncodeNumericValue key error");
            return {};
        }
        if (!EncodeNumericValue(static_cast<uint32_t>(value.size()), length)) {
            IAM_LOGE("EncodeNumericValue value error");
            return {};
        }

        buffer.insert(buffer.end(), type.begin(), type.end());
        buffer.insert(buffer.end(), length.begin(), length.end());
        buffer.insert(buffer.end(), value.begin(), value.end());
    }

    return buffer;
}

std::vector<Attributes::AttributeKey> Attributes::GetKeys() const
{
    std::vector<AttributeKey> keys;
    keys.reserve(map_.size());
    for (const auto &[key, value] : map_) {
        keys.push_back(key);
    }
    return keys;
}

bool Attributes::HasAttribute(AttributeKey key) const
{
    return map_.find(key) != map_.end();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS