/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <climits>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "iam_logger.h"

#include "cda_attributes.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using namespace testing;
using namespace testing::ext;

namespace {
} // namespace

class AttributesTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override;
    void TearDown() override;
};

void AttributesTest::SetUpTestCase()
{
}

void AttributesTest::TearDownTestCase()
{
}

void AttributesTest::SetUp()
{
}

void AttributesTest::TearDown()
{
}

HWTEST_F(AttributesTest, AttributesInit, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_EQ(attrs.Serialize().size(), 0U);
}

HWTEST_F(AttributesTest, AttributesSerialize, TestSize.Level0)
{
    const std::vector<Attributes::AttributeKey> desired = { Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        Attributes::ATTR_CDA_SA_RESULT, Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID, Attributes::ATTR_CDA_SA_CHALLENGE,
        Attributes::ATTR_CDA_SA_MSG_TYPE };

    Attributes attrs;

    attrs.SetBoolValue(Attributes::ATTR_CDA_SA_RESULT, true);
    attrs.SetBoolValue(Attributes::ATTR_SIGNATURE, false);
    attrs.SetUint32ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, { 1, 3, 5, 7, 9 });
    attrs.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, UINT16_MAX);
    attrs.SetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID, UINT16_MAX);
    attrs.SetUint64ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, { 2, 4, 6, 8, 10 });
    attrs.SetStringValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, "iam");

    EXPECT_THAT(attrs.GetKeys(), ElementsAreArray(desired));
    auto buff = attrs.Serialize();
    Attributes attrs2(buff);
    EXPECT_THAT(attrs2.GetKeys(), ElementsAreArray(desired));

    bool boolValue;
    EXPECT_TRUE(attrs2.GetBoolValue(Attributes::ATTR_CDA_SA_RESULT, boolValue));
    EXPECT_EQ(boolValue, true);

    EXPECT_TRUE(attrs2.GetBoolValue(Attributes::ATTR_SIGNATURE, boolValue));
    EXPECT_EQ(boolValue, false);

    std::vector<uint32_t> u32Vector;
    EXPECT_TRUE(attrs2.GetUint32ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, u32Vector));
    EXPECT_THAT(u32Vector, ElementsAre(1, 3, 5, 7, 9));

    uint16_t u16ValueForMsg;
    EXPECT_TRUE(attrs2.GetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, u16ValueForMsg));
    EXPECT_EQ(u16ValueForMsg, UINT16_MAX);

    uint16_t u16Value;
    EXPECT_TRUE(attrs2.GetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID, u16Value));
    EXPECT_EQ(u16Value, UINT16_MAX);

    std::vector<uint64_t> u64Vector;
    EXPECT_TRUE(attrs2.GetUint64ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, u64Vector));
    EXPECT_THAT(u64Vector, ElementsAre(2, 4, 6, 8, 10));

    std::string str;
    EXPECT_TRUE(attrs2.GetStringValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, str));
    EXPECT_EQ(str, "iam");
}

HWTEST_F(AttributesTest, AttributesBoolValue, TestSize.Level0)
{
    Attributes attrs;
    attrs.SetBoolValue(Attributes::ATTR_CDA_SA_RESULT, true);
    attrs.SetBoolValue(Attributes::ATTR_SIGNATURE, false);

    bool value1;
    bool value2;
    EXPECT_TRUE(attrs.GetBoolValue(Attributes::ATTR_CDA_SA_RESULT, value1));
    EXPECT_TRUE(attrs.GetBoolValue(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_TRUE(value1);
    EXPECT_FALSE(value2);
}

HWTEST_F(AttributesTest, AttributesUint64Value, TestSize.Level0)
{
    Attributes attrs;
    uint64_t value1;
    uint64_t value2;
    EXPECT_FALSE(attrs.GetUint64Value(Attributes::ATTR_CDA_SA_RESULT, value1));
    EXPECT_FALSE(attrs.GetUint64Value(Attributes::ATTR_SIGNATURE, value2));

    attrs.SetUint64Value(Attributes::ATTR_CDA_SA_RESULT, UINT32_MAX);
    attrs.SetUint64Value(Attributes::ATTR_SIGNATURE, UINT64_MAX);

    EXPECT_TRUE(attrs.GetUint64Value(Attributes::ATTR_CDA_SA_RESULT, value1));
    EXPECT_TRUE(attrs.GetUint64Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_EQ(value1, UINT32_MAX);
    EXPECT_EQ(value2, UINT64_MAX);
}

HWTEST_F(AttributesTest, AttributesUint32Value, TestSize.Level0)
{
    Attributes attrs;
    attrs.SetUint32Value(Attributes::ATTR_CDA_SA_RESULT, UINT16_MAX);
    attrs.SetUint32Value(Attributes::ATTR_SIGNATURE, UINT32_MAX);

    uint32_t value1;
    uint32_t value2;
    EXPECT_TRUE(attrs.GetUint32Value(Attributes::ATTR_CDA_SA_RESULT, value1));
    EXPECT_TRUE(attrs.GetUint32Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_TRUE(value1 == UINT16_MAX);
    EXPECT_TRUE(value2 == UINT32_MAX);
}

HWTEST_F(AttributesTest, AttributesUint16Value, TestSize.Level0)
{
    Attributes attrs;
    attrs.SetUint16Value(Attributes::ATTR_CDA_SA_RESULT, UINT8_MAX);
    attrs.SetUint16Value(Attributes::ATTR_SIGNATURE, UINT16_MAX);

    uint16_t value1;
    uint16_t value2;
    EXPECT_TRUE(attrs.GetUint16Value(Attributes::ATTR_CDA_SA_RESULT, value1));
    EXPECT_TRUE(attrs.GetUint16Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_TRUE(value1 == UINT8_MAX);
    EXPECT_TRUE(value2 == UINT16_MAX);
}

HWTEST_F(AttributesTest, AttributesUint8Value, TestSize.Level0)
{
    Attributes attrs;

    uint8_t value1;
    uint8_t value2;
    EXPECT_FALSE(attrs.GetUint8Value(Attributes::ATTR_CDA_SA_RESULT, value1));
    EXPECT_FALSE(attrs.GetUint8Value(Attributes::ATTR_SIGNATURE, value2));
    attrs.SetUint8Value(Attributes::ATTR_CDA_SA_RESULT, 0);
    attrs.SetUint8Value(Attributes::ATTR_SIGNATURE, UINT8_MAX);

    EXPECT_TRUE(attrs.GetUint8Value(Attributes::ATTR_CDA_SA_RESULT, value1));
    EXPECT_TRUE(attrs.GetUint8Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_EQ(value1, 0);
    EXPECT_EQ(value2, UINT8_MAX);
}

HWTEST_F(AttributesTest, AttributesStringValue, TestSize.Level0)
{
    Attributes attrs;
    attrs.SetStringValue(Attributes::ATTR_CDA_SA_RESULT, "hello iam");
    attrs.SetStringValue(Attributes::ATTR_SIGNATURE, "");

    std::string value1;
    std::string value2;
    EXPECT_TRUE(attrs.GetStringValue(Attributes::ATTR_CDA_SA_RESULT, value1));
    EXPECT_TRUE(attrs.GetStringValue(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_EQ(value1, "hello iam");
    EXPECT_EQ(value2, "");
}

HWTEST_F(AttributesTest, AttributesUint64ByteArray, TestSize.Level0)
{
    {
        constexpr int arraySize = 4096;

        Attributes attrs;
        std::vector<uint64_t> array;
        array.reserve(arraySize);
        for (int i = 0; i < arraySize; i++) {
            array.push_back(UINT64_MAX - i);
        }
        attrs.SetUint64ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array);

        std::vector<uint64_t> out;
        EXPECT_TRUE(attrs.GetUint64ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }

    {
        Attributes attrs;
        std::vector<uint64_t> array;
        attrs.SetUint64ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array);
        EXPECT_TRUE(attrs.GetUint64ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesUint32ByteArray, TestSize.Level0)
{
    {
        constexpr int arraySize = 4096;

        Attributes attrs;
        std::vector<uint32_t> array;
        array.reserve(arraySize);
        for (int i = 0; i < arraySize; i++) {
            array.push_back(UINT32_MAX - i);
        }

        std::vector<uint32_t> out;
        EXPECT_FALSE(attrs.GetUint32ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, out));
        attrs.SetUint32ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array);

        EXPECT_TRUE(attrs.GetUint32ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }
    {
        Attributes attrs;
        std::vector<uint32_t> array;
        attrs.SetUint32ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array);

        EXPECT_TRUE(attrs.GetUint32ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesUint16ByteArray, TestSize.Level0)
{
    {
        constexpr int arraySize = 4096;

        Attributes attrs;
        std::vector<uint16_t> array;
        array.reserve(arraySize);
        for (int i = 0; i < arraySize; i++) {
            array.push_back(UINT16_MAX - i);
        }
        attrs.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array);

        std::vector<uint16_t> out;
        EXPECT_TRUE(attrs.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }
    {
        Attributes attrs;
        std::vector<uint16_t> array;
        attrs.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array);

        EXPECT_TRUE(attrs.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesUint8ByteArray, TestSize.Level0)
{
    {
        constexpr int arraySize = 4096;

        Attributes attrs;
        std::vector<uint8_t> array;
        array.reserve(arraySize);
        for (int i = 0; i < arraySize; i++) {
            array.push_back(i);
        }
        attrs.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array);

        std::vector<uint8_t> out;
        EXPECT_TRUE(attrs.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }
    {
        Attributes attrs;
        std::vector<uint8_t> array;
        attrs.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array);

        EXPECT_TRUE(attrs.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesDeserializeMismatch, TestSize.Level0)
{
    const std::vector<uint8_t> raw = { 0, 0, 0, 0, 1, 0, 0, 0, 1, 2, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 5, 0,
        0, 0, 7, 0, 0, 0, 9, 0, 0, 0, 3, 0, 0, 0, 40, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0,
        0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0, 5, 0, 0, 0, 4, 0, 0,
        0, 255, 255, 255, 255, 6, 0, 0, 0, 8, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 7, 0, 0, 0, 4, 0, 0, 0,
        105, 97, 109, 0 };

    Attributes attrs(raw);
    {
        bool value;
        EXPECT_FALSE(attrs.GetBoolValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, value));
    }
    {
        uint16_t value;
        EXPECT_FALSE(attrs.GetUint16Value(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, value));
    }
}

HWTEST_F(AttributesTest, AttributesEmptyArrays, TestSize.Level0)
{
    Attributes attrs1;
    bool value = true;
    attrs1.SetBoolValue(Attributes::ATTR_CDA_SA_RESULT, value);

    std::vector<uint32_t> u32Vector;
    attrs1.SetUint32ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, u32Vector);

    std::vector<uint16_t> u16Vector;
    EXPECT_FALSE(attrs1.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, u16Vector));
    attrs1.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, u16Vector);

    std::vector<uint8_t> u8Vector;
    attrs1.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, u8Vector);

    auto buff = attrs1.Serialize();
    EXPECT_FALSE(buff.empty());
    Attributes attrs2(buff);
    EXPECT_TRUE(attrs1.GetBoolValue(Attributes::ATTR_CDA_SA_RESULT, value));
    EXPECT_TRUE(value);

    EXPECT_TRUE(attrs1.GetUint32ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, u32Vector));
    EXPECT_THAT(u32Vector, IsEmpty());

    EXPECT_TRUE(attrs1.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, u16Vector));
    EXPECT_THAT(u16Vector, IsEmpty());

    EXPECT_TRUE(attrs1.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, u8Vector));
    EXPECT_THAT(u8Vector, IsEmpty());
}

HWTEST_F(AttributesTest, AttributesCopyAndMove, TestSize.Level0)
{
    EXPECT_TRUE(std::is_copy_assignable<Attributes>::value);
    EXPECT_TRUE(std::is_copy_constructible<Attributes>::value);

    const std::vector<uint8_t> raw = { 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0,
        255, 255, 255, 255, 3, 0, 0, 0, 8, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 4, 0, 0, 0, 4, 0, 0, 0, 105,
        97, 109, 0, 5, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0, 7, 0, 0, 0, 9, 0, 0, 0, 6, 0, 0, 0, 40,
        0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 10, 0,
        0, 0, 0, 0, 0, 0 };
    Attributes attrs1(raw);

    EXPECT_THAT(attrs1.Serialize(), ElementsAreArray(raw));

    Attributes attrs2 = std::move(attrs1);

    EXPECT_EQ(attrs1.Serialize().size(), 0U);
    EXPECT_THAT(attrs2.Serialize(), ElementsAreArray(raw));
}

HWTEST_F(AttributesTest, AttributesSetAndGetAttributesArray, TestSize.Level0)
{
    Attributes attrs1;
    Attributes attrs2;
    attrs1.SetBoolValue(Attributes::ATTR_CDA_SA_RESULT, true);
    attrs2.SetBoolValue(Attributes::ATTR_CDA_SA_RESULT, true);

    std::vector<Attributes> attrsArray;
    attrsArray.push_back(Attributes(attrs1.Serialize()));
    attrsArray.push_back(Attributes(attrs2.Serialize()));

    Attributes setAttrs;
    setAttrs.SetAttributesArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, attrsArray);

    std::vector<uint8_t> data = setAttrs.Serialize();
    EXPECT_TRUE(data.size() > 0);

    Attributes getAttrs(data);
    std::vector<Attributes> getAttrsArray;
    EXPECT_TRUE(getAttrs.GetAttributesArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, getAttrsArray));

    ASSERT_EQ(getAttrsArray.size(), 2);
    std::vector<uint8_t> serializedAttrs1 = attrs1.Serialize();
    std::vector<uint8_t> serializedAttrs2 = attrs2.Serialize();

    std::vector<uint8_t> serializedOutAttrs1 = getAttrsArray[0].Serialize();
    std::vector<uint8_t> serializedOutAttrs2 = getAttrsArray[1].Serialize();

    EXPECT_TRUE(serializedAttrs1 == serializedOutAttrs1);
    EXPECT_TRUE(serializedAttrs2 == serializedOutAttrs2);
}

HWTEST_F(AttributesTest, AttributesSetAndGetAttributesArray01, TestSize.Level0)
{
    Attributes attrs1;
    int64_t value1 = 1;
    int64_t value2 = 2;
    attrs1.SetInt64Value(Attributes::ATTR_CDA_SA_EXTRA_INFO, value2);
    EXPECT_EQ(attrs1.GetInt64Value(Attributes::ATTR_CDA_SA_EXTRA_INFO, value1), true);
    EXPECT_EQ(value1, value2);

    Attributes setAttrs;
    Attributes attrs2;
    std::vector<int32_t> array2;
    EXPECT_EQ(setAttrs.GetInt32ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, array2), false);
    EXPECT_EQ(setAttrs.GetAttributesValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, attrs2), false);
    setAttrs.SetAttributesValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, attrs1);
    EXPECT_EQ(setAttrs.GetAttributesValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, attrs2), true);

    std::vector<int32_t> array1;
    array1.push_back(1);
    setAttrs.SetInt32ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, array1);
    EXPECT_EQ(setAttrs.GetInt32ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, array2), true);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint64Value, TestSize.Level0)
{
    Attributes attrs;
    uint64_t encodeVal64 = 0x0102030405060708;
    uint64_t encodeVal32 = 0x01020304;

    attrs.SetUint64Value(Attributes::ATTR_SIGNATURE, encodeVal64);
    attrs.SetUint64Value(Attributes::ATTR_CDA_SA_RESULT, encodeVal32);

    uint64_t decodeVal64;
    uint64_t decodeVal32;

    EXPECT_TRUE(attrs.GetUint64Value(Attributes::ATTR_SIGNATURE, decodeVal64));
    EXPECT_TRUE(attrs.GetUint64Value(Attributes::ATTR_CDA_SA_RESULT, decodeVal32));

    EXPECT_EQ(encodeVal64, decodeVal64);
    EXPECT_EQ(encodeVal32, decodeVal32);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint32Value, TestSize.Level0)
{
    Attributes attrs;
    uint32_t encodeVal32 = 0x01020304;
    uint32_t encodeVal16 = 0x0102;

    attrs.SetUint32Value(Attributes::ATTR_SIGNATURE, encodeVal32);
    attrs.SetUint32Value(Attributes::ATTR_CDA_SA_RESULT, encodeVal16);

    uint32_t decodeVal32;
    uint32_t decodeVal16;

    EXPECT_TRUE(attrs.GetUint32Value(Attributes::ATTR_SIGNATURE, decodeVal32));
    EXPECT_TRUE(attrs.GetUint32Value(Attributes::ATTR_CDA_SA_RESULT, decodeVal16));

    EXPECT_EQ(encodeVal32, decodeVal32);
    EXPECT_EQ(encodeVal16, decodeVal16);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint16Value, TestSize.Level0)
{
    Attributes attrs;
    uint16_t encodeVal16 = 0x0102;
    uint16_t encodeVal8 = 0x01;

    attrs.SetUint16Value(Attributes::ATTR_SIGNATURE, encodeVal16);
    attrs.SetUint16Value(Attributes::ATTR_CDA_SA_RESULT, encodeVal8);

    uint16_t decodeVal16;
    uint16_t decodeVal8;

    EXPECT_TRUE(attrs.GetUint16Value(Attributes::ATTR_SIGNATURE, decodeVal16));
    EXPECT_TRUE(attrs.GetUint16Value(Attributes::ATTR_CDA_SA_RESULT, decodeVal8));

    EXPECT_EQ(encodeVal16, decodeVal16);
    EXPECT_EQ(encodeVal8, decodeVal8);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeInt64Value, TestSize.Level0)
{
    Attributes attrs;
    int64_t encodeVal64 = 0x0102030405060708;
    int64_t encodeVal32 = 0x01020304;

    attrs.SetInt64Value(Attributes::ATTR_CDA_SA_EXTRA_INFO, encodeVal64);
    attrs.SetInt64Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, encodeVal32);

    int64_t decodeVal64;
    int64_t decodeVal32;

    EXPECT_TRUE(attrs.GetInt64Value(Attributes::ATTR_CDA_SA_EXTRA_INFO, decodeVal64));
    EXPECT_TRUE(attrs.GetInt64Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, decodeVal32));

    EXPECT_EQ(encodeVal64, decodeVal64);
    EXPECT_EQ(encodeVal32, decodeVal32);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeInt32Value, TestSize.Level0)
{
    Attributes attrs;
    int32_t encodeVal32 = 0x01020304;
    int32_t encodeVal16 = 0x0102;

    attrs.SetInt32Value(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, encodeVal32);
    attrs.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, encodeVal16);

    int32_t decodeVal32;
    int32_t decodeVal16;

    EXPECT_TRUE(attrs.GetInt32Value(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, decodeVal32));
    EXPECT_TRUE(attrs.GetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, decodeVal16));

    EXPECT_EQ(encodeVal32, decodeVal32);
    EXPECT_EQ(encodeVal16, decodeVal16);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint64Array, TestSize.Level0)
{
    {
        Attributes attrsEmpty;
        std::vector<uint64_t> encodeEmptyArray;
        std::vector<uint64_t> decodeEmptyArray;
        attrsEmpty.SetUint64ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, encodeEmptyArray);
        EXPECT_TRUE(attrsEmpty.GetUint64ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, decodeEmptyArray));
        EXPECT_THAT(encodeEmptyArray, decodeEmptyArray);
    }

    {
        Attributes attrs;
        constexpr int arraySize = 1024;
        std::vector<uint64_t> encodeArray;
        std::vector<uint64_t> decodeArray;
        encodeArray.reserve(arraySize);
        for (int i = 0; i < arraySize; i++) {
            encodeArray.push_back(UINT64_MAX - i);
        }
        attrs.SetUint64ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, encodeArray);
        EXPECT_TRUE(attrs.GetUint64ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, decodeArray));
        EXPECT_THAT(encodeArray, decodeArray);
    }
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint32Array, TestSize.Level0)
{
    {
        Attributes attrsEmpty;
        std::vector<uint32_t> encodeEmptyArray;
        std::vector<uint32_t> decodeEmptyArray;
        attrsEmpty.SetUint32ArrayValue(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, encodeEmptyArray);
        EXPECT_TRUE(attrsEmpty.GetUint32ArrayValue(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, decodeEmptyArray));
        EXPECT_THAT(encodeEmptyArray, decodeEmptyArray);
    }

    {
        Attributes attrs;
        constexpr int arraySize = 1024;
        std::vector<uint32_t> encodeArray;
        std::vector<uint32_t> decodeArray;
        encodeArray.reserve(arraySize);
        for (int i = 0; i < arraySize; i++) {
            encodeArray.push_back(UINT32_MAX - i);
        }
        attrs.SetUint32ArrayValue(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, encodeArray);
        EXPECT_TRUE(attrs.GetUint32ArrayValue(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, decodeArray));
        EXPECT_THAT(encodeArray, decodeArray);
    }
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint16Array, TestSize.Level0)
{
    {
        Attributes attrsEmpty;
        std::vector<uint16_t> encodeEmptyArray;
        std::vector<uint16_t> decodeEmptyArray;
        attrsEmpty.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, encodeEmptyArray);
        EXPECT_TRUE(attrsEmpty.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, decodeEmptyArray));
        EXPECT_THAT(encodeEmptyArray, decodeEmptyArray);
    }

    {
        Attributes attrs;
        constexpr int arraySize = 1024;
        std::vector<uint16_t> encodeArray;
        std::vector<uint16_t> decodeArray;
        encodeArray.reserve(arraySize);
        for (int i = 0; i < arraySize; i++) {
            encodeArray.push_back(UINT16_MAX - i);
        }
        attrs.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, encodeArray);
        EXPECT_TRUE(attrs.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, decodeArray));
        EXPECT_THAT(encodeArray, decodeArray);
    }
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeInt32Array, TestSize.Level0)
{
    {
        Attributes attrsEmpty;
        std::vector<int32_t> encodeEmptyArray;
        std::vector<int32_t> decodeEmptyArray;
        attrsEmpty.SetInt32ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, encodeEmptyArray);
        EXPECT_TRUE(attrsEmpty.GetInt32ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, decodeEmptyArray));
        EXPECT_THAT(encodeEmptyArray, decodeEmptyArray);
    }

    {
        Attributes attrs;
        constexpr int arraySize = 1024;
        std::vector<int32_t> encodeArray;
        std::vector<int32_t> decodeArray;
        encodeArray.reserve(arraySize);
        for (int i = 0; i < arraySize; i++) {
            encodeArray.push_back(INT32_MAX - i);
        }
        attrs.SetInt32ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, encodeArray);
        EXPECT_TRUE(attrs.GetInt32ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, decodeArray));
        EXPECT_THAT(encodeArray, decodeArray);
    }
}

HWTEST_F(AttributesTest, AttributesSerializeAndDeserialize01, TestSize.Level0)
{
    const uint64_t constU64Val = 0x0102030405060708;
    const uint32_t constU32Val = 0x01020304;
    const uint16_t constU16Val = 0x0102;
    const int32_t constI32Val = 0x01020304;
    Attributes attrsSerial;
    attrsSerial.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, constU16Val);
    attrsSerial.SetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID, constU16Val);
    attrsSerial.SetUint64ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE,
        { constU64Val, constU64Val, constU64Val, constU64Val, constU64Val });
    attrsSerial.SetUint32ArrayValue(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM,
        { constU32Val, constU32Val, constU32Val, constU32Val, constU32Val });
    attrsSerial.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, constI32Val);
    attrsSerial.SetInt32ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST,
        { constI32Val, constI32Val, constI32Val, constI32Val, constI32Val });
    int64_t testInt64Val = 100;
    attrsSerial.SetInt64Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, testInt64Val);
    auto buffer = attrsSerial.Serialize();

    Attributes attrsDeserial(buffer);
    uint16_t u16ValueForMsg;
    EXPECT_TRUE(attrsDeserial.GetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, u16ValueForMsg));
    EXPECT_EQ(u16ValueForMsg, constU16Val);
    uint16_t u16Value;
    EXPECT_TRUE(attrsDeserial.GetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID, u16Value));
    EXPECT_EQ(u16Value, constU16Val);
    std::vector<uint64_t> u64Vector;
    EXPECT_TRUE(attrsDeserial.GetUint64ArrayValue(Attributes::ATTR_CDA_SA_CHALLENGE, u64Vector));
    EXPECT_THAT(u64Vector, ElementsAre(constU64Val, constU64Val, constU64Val, constU64Val, constU64Val));
    std::vector<uint32_t> u32Vector;
    EXPECT_TRUE(attrsDeserial.GetUint32ArrayValue(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, u32Vector));
    EXPECT_THAT(u32Vector, ElementsAre(constU32Val, constU32Val, constU32Val, constU32Val, constU32Val));
    int32_t int32Value;
    EXPECT_TRUE(attrsDeserial.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, int32Value));
    EXPECT_EQ(int32Value, constI32Val);
    std::vector<int32_t> int32_vector;
    EXPECT_TRUE(attrsDeserial.GetInt32ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, int32_vector));
    EXPECT_THAT(int32_vector, ElementsAre(constI32Val, constI32Val, constI32Val, constI32Val, constI32Val));
    int64_t int64Value;
    EXPECT_TRUE(attrsDeserial.GetInt64Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, int64Value));
    EXPECT_EQ(int64Value, 100);
}

HWTEST_F(AttributesTest, AttributesSerializeAndDeserialize02, TestSize.Level0)
{
    const uint32_t constU32Val = 0x01020304;
    const uint16_t constU16Val = 0x0102;
    const uint8_t constU8Val = 0x01;
    Attributes attrsSerial;
    attrsSerial.SetBoolValue(Attributes::ATTR_CDA_SA_AUTH_STATE_MAINTAIN, true);
    attrsSerial.SetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, false);
    attrsSerial.SetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, constU16Val);
    attrsSerial.SetUint32ArrayValue(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM,
        { constU32Val, constU32Val, constU32Val, constU32Val, constU32Val });
    attrsSerial.SetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, "iam_unit_test");
    attrsSerial.SetUint8Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, constU8Val);
    attrsSerial.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_SALT,
        { constU8Val, constU8Val, constU8Val, constU8Val, constU8Val });
    auto buffer = attrsSerial.Serialize();

    Attributes attrsDeserial(buffer);
    bool boolValTrue;
    EXPECT_TRUE(attrsDeserial.GetBoolValue(Attributes::ATTR_CDA_SA_AUTH_STATE_MAINTAIN, boolValTrue));
    EXPECT_EQ(boolValTrue, true);

    bool boolValFalse;
    EXPECT_TRUE(attrsDeserial.GetBoolValue(Attributes::ATTR_CDA_SA_MSG_ACK, boolValFalse));
    EXPECT_EQ(boolValFalse, false);

    uint16_t u16ValueForMsg;
    EXPECT_TRUE(attrsDeserial.GetUint16Value(Attributes::ATTR_CDA_SA_MSG_TYPE, u16ValueForMsg));
    EXPECT_EQ(u16ValueForMsg, constU16Val);

    std::vector<uint32_t> u32Vector;
    EXPECT_TRUE(attrsDeserial.GetUint32ArrayValue(Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, u32Vector));
    EXPECT_THAT(u32Vector, ElementsAre(constU32Val, constU32Val, constU32Val, constU32Val, constU32Val));

    std::string strValue;
    EXPECT_TRUE(attrsDeserial.GetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, strValue));
    EXPECT_EQ(strValue, "iam_unit_test");

    uint8_t u8Value;
    EXPECT_TRUE(attrsDeserial.GetUint8Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, u8Value));
    EXPECT_EQ(u8Value, constU8Val);

    std::vector<uint8_t> u8Vector;
    EXPECT_TRUE(attrsDeserial.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_SALT, u8Vector));
    EXPECT_THAT(u8Vector, ElementsAre(constU8Val, constU8Val, constU8Val, constU8Val, constU8Val));
}

HWTEST_F(AttributesTest, AttributesRawSerializeTest01, TestSize.Level0)
{
    std::vector<uint8_t> raw = { 160, 134, 1, 0, 1, 0, 0, 0, 255, 175, 134, 1, 0, 14, 0, 0, 0, 105, 97, 109, 95, 117,
        110, 105, 116, 95, 116, 101, 115, 116, 0, 180, 134, 1, 0, 5, 0, 0, 0, 255, 255, 255, 255, 255, 182, 134, 1, 0,
        4, 0, 0, 0, 255, 255, 255, 255, 197, 134, 1, 0, 20, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 198, 134, 1, 0, 1, 0, 0, 0, 1, 213, 134, 1, 0, 1, 0, 0, 0,
        0 };

    Attributes attrs(raw);
    std::vector<uint8_t> buffer = attrs.Serialize();
    for (int i = 0; i < buffer.size(); i++) {
        EXPECT_THAT(raw[i], buffer[i]);
    }
}

HWTEST_F(AttributesTest, AttributesRawSerializeTest03, TestSize.Level0)
{
    std::vector<uint8_t> raw = { 169, 134, 1, 0, 4, 0, 0, 0, 255, 255, 255, 127, 170, 134, 1, 0, 40, 0, 0, 0, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 177, 134, 1, 0, 8, 0, 0, 0, 255,
        255, 255, 255, 255, 255, 255, 255, 182, 134, 1, 0, 4, 0, 0, 0, 255, 255, 255, 255, 197, 134, 1, 0, 20, 0, 0, 0,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 210, 134, 1,
        0, 2, 0, 0, 0, 255, 255, 234, 134, 1, 0, 20, 0, 0, 0, 255, 255, 255, 127, 255, 255, 255, 127, 255, 255, 255,
        127, 255, 255, 255, 127, 255, 255, 255, 127, 243, 134, 1, 0, 8, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0 };

    Attributes attrs(raw);
    std::vector<uint8_t> buffer = attrs.Serialize();
    for (int i = 0; i < buffer.size(); i++) {
        EXPECT_THAT(raw[i], buffer[i]);
    }
}

HWTEST_F(AttributesTest, AttributesTest01, TestSize.Level0)
{
    IAM_LOGI("AttributesTest01 begin\n");
    std::vector<uint8_t> extraInfo = { 0 };
    Attributes attribute = Attributes(extraInfo);
    extraInfo.resize(16);
    EXPECT_NO_THROW(extraInfo.resize(24));
    attribute.~Attributes();
    uint64_t attrValue = 0;
    attribute.SetUint64Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, attrValue);
    attribute.SetBoolValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, true);
    uint32_t uint32Value = 0;
    attribute.SetUint32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, uint32Value);
    uint16_t uint16Value = 0;
    attribute.SetUint16Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, uint16Value);
    uint8_t uint8Value = 0;
    attribute.SetUint8Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, uint8Value);
    int32_t int32Value = 0;
    attribute.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, int32Value);
    int64_t int64Value = 0;
    attribute.SetInt64Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, int64Value);
    std::string stringValue = "";
    attribute.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, stringValue);
    std::vector<uint64_t> uint64ArrayValue = {};
    attribute.SetUint64ArrayValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, uint64ArrayValue);
    std::vector<uint32_t> uint32ArrayValue = {};
    attribute.SetUint32ArrayValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, uint32ArrayValue);
    std::vector<uint16_t> uint16ArrayValue = {};
    attribute.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, uint16ArrayValue);
    std::vector<uint8_t> uint8ArrayValue = {};
    attribute.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, uint8ArrayValue);
    std::vector<int32_t> int32ArrayValue = {};
    attribute.SetInt32ArrayValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, int32ArrayValue);
    Attributes AttributesValue = Attributes(extraInfo);
    attribute.SetAttributesValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, AttributesValue);
    IAM_LOGI("AttributesTest01 end\n");
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
