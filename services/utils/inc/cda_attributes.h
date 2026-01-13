/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

/**
 * @file cda_attributes.h
 *
 * @brief Attributes enum define.
 * @since 3.1
 * @version 3.2
 */

#ifndef COMPANION_DEVICE_AUTH_CDA_ATTRIBUTES_H
#define COMPANION_DEVICE_AUTH_CDA_ATTRIBUTES_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class Attributes final {
public:
    /**
     * @brief The key to set attribute.
     */
    enum AttributeKey : uint32_t {
        /** Signature, the value type is std::vector<uint8_t>. */
        ATTR_SIGNATURE = 100004,

        /** Companion device auth SA specific attributes begin from 200000 */
        ATTR_CDA_SA_BEGIN = 200000,
        ATTR_CDA_SA_PROTOCOL_ID_LIST = 200001,
        ATTR_CDA_SA_CAPABILITY_LIST = 200002,
        ATTR_CDA_SA_HOST_USER_ID = 200003,
        ATTR_CDA_SA_EXTRA_INFO = 200004, // std::vector<uint8_t>
        ATTR_CDA_SA_RESULT = 200005,
        ATTR_CDA_SA_SECURE_PROTOCOL_ID = 200006,
        ATTR_CDA_SA_COMPANION_USER_ID = 200007,
        ATTR_CDA_SA_USER_NAME = 200008,
        ATTR_CDA_SA_DEVICE_NAME = 200009,
        ATTR_CDA_SA_MODEL = 200010,
        ATTR_CDA_SA_AUTH_STATE_MAINTAIN = 200013,
        ATTR_CDA_SA_SRC_IDENTIFIER = 200014,
        ATTR_CDA_SA_SRC_IDENTIFIER_TYPE = 200015,
        ATTR_CDA_SA_CONNECTION_NAME = 200017,
        ATTR_CDA_SA_SALT = 200018,
        ATTR_CDA_SA_CHALLENGE = 200019,
        ATTR_CDA_SA_MSG_TYPE = 200020,
        ATTR_CDA_SA_MSG_ACK = 200021,
        ATTR_CDA_SA_MSG_SEQ_NUM = 200022,
        ATTR_CDA_SA_REASON = 200024,
        // ATTR_CDA_SA_USER_NAME = 200008,
        /** Companion device auth secure specific attributes begin from 300000 */
        ATTR_CDA_SECURE_BEGIN = 300000,
    };

    Attributes();
    explicit Attributes(const std::vector<uint8_t> &raw);
    Attributes(const Attributes &other);
    Attributes &operator=(const Attributes &other);
    Attributes(Attributes &&other) noexcept;
    Attributes &operator=(Attributes &&other) noexcept;
    virtual ~Attributes();

    void SetBoolValue(AttributeKey key, bool value);
    void SetUint64Value(AttributeKey key, uint64_t value);
    void SetUint32Value(AttributeKey key, uint32_t value);
    void SetUint16Value(AttributeKey key, uint16_t value);
    void SetUint8Value(AttributeKey key, uint8_t value);
    void SetInt32Value(AttributeKey key, int32_t value);
    void SetInt64Value(AttributeKey key, int64_t value);
    void SetStringValue(AttributeKey key, const std::string &value);
    void SetAttributesValue(AttributeKey key, const Attributes &value);
    void SetAttributesArrayValue(AttributeKey key, const std::vector<Attributes> &array);
    void SetUint64ArrayValue(AttributeKey key, const std::vector<uint64_t> &value);
    void SetUint32ArrayValue(AttributeKey key, const std::vector<uint32_t> &value);
    void SetInt32ArrayValue(AttributeKey key, const std::vector<int32_t> &value);
    void SetUint16ArrayValue(AttributeKey key, const std::vector<uint16_t> &value);
    void SetUint8ArrayValue(AttributeKey key, const std::vector<uint8_t> &value);

    bool GetBoolValue(AttributeKey key, bool &value) const;
    bool GetUint64Value(AttributeKey key, uint64_t &value) const;
    bool GetUint32Value(AttributeKey key, uint32_t &value) const;
    bool GetUint16Value(AttributeKey key, uint16_t &value) const;
    bool GetUint8Value(AttributeKey key, uint8_t &value) const;
    bool GetInt32Value(AttributeKey key, int32_t &value) const;
    bool GetInt64Value(AttributeKey key, int64_t &value) const;
    bool GetStringValue(AttributeKey key, std::string &value) const;
    bool GetUint64ArrayValue(AttributeKey key, std::vector<uint64_t> &value) const;
    bool GetUint32ArrayValue(AttributeKey key, std::vector<uint32_t> &value) const;
    bool GetInt32ArrayValue(AttributeKey key, std::vector<int32_t> &value) const;
    bool GetUint16ArrayValue(AttributeKey key, std::vector<uint16_t> &value) const;
    bool GetUint8ArrayValue(AttributeKey key, std::vector<uint8_t> &value) const;
    bool GetAttributesValue(AttributeKey key, Attributes &value) const;
    bool GetAttributesArrayValue(AttributeKey key, std::vector<Attributes> &array) const;

    std::vector<uint8_t> Serialize() const;
    std::vector<AttributeKey> GetKeys() const;
    bool HasAttribute(AttributeKey key) const;

#ifndef ENABLE_TEST
private:
#endif
    std::map<AttributeKey, std::vector<uint8_t>> map_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_CDA_ATTRIBUTES_H
