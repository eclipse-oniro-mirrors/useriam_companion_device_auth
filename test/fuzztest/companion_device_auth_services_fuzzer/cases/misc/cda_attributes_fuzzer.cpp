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

#include <cstdint>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "cda_attributes.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr uint32_t SIZE_64 = 64;
constexpr int32_t INT32_5 = 5;
constexpr uint32_t SIZE_1024 = 1024;
} // namespace

using CdaAttributesFuzzFunction = void (*)(FuzzedDataProvider &, Attributes::AttributeKey);

static void FuzzOp0(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetBoolValue / GetBoolValue
    Attributes attr;
    bool boolValue = fuzzData.ConsumeBool();
    attr.SetBoolValue(fuzzKey, boolValue);
    bool result;
    attr.GetBoolValue(fuzzKey, result);
}

static void FuzzOp1(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetUint64Value / GetUint64Value
    Attributes attr;
    uint64_t uint64Value = fuzzData.ConsumeIntegral<uint64_t>();
    attr.SetUint64Value(fuzzKey, uint64Value);
    uint64_t result;
    attr.GetUint64Value(fuzzKey, result);
}

static void FuzzOp2(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetUint32Value / GetUint32Value
    Attributes attr;
    uint32_t uint32Value = fuzzData.ConsumeIntegral<uint32_t>();
    attr.SetUint32Value(fuzzKey, uint32Value);
    uint32_t result;
    attr.GetUint32Value(fuzzKey, result);
}

static void FuzzOp3(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetUint16Value / GetUint16Value
    Attributes attr;
    uint16_t uint16Value = fuzzData.ConsumeIntegral<uint16_t>();
    attr.SetUint16Value(fuzzKey, uint16Value);
    uint16_t result;
    attr.GetUint16Value(fuzzKey, result);
}

static void FuzzOp4(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetUint8Value / GetUint8Value
    Attributes attr;
    uint8_t uint8Value = fuzzData.ConsumeIntegral<uint8_t>();
    attr.SetUint8Value(fuzzKey, uint8Value);
    uint8_t result;
    attr.GetUint8Value(fuzzKey, result);
}

static void FuzzOp5(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetInt32Value / GetInt32Value
    Attributes attr;
    int32_t int32Value = fuzzData.ConsumeIntegral<int32_t>();
    attr.SetInt32Value(fuzzKey, int32Value);
    int32_t result;
    attr.GetInt32Value(fuzzKey, result);
}

static void FuzzOp6(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetInt64Value / GetInt64Value
    Attributes attr;
    int64_t int64Value = fuzzData.ConsumeIntegral<int64_t>();
    attr.SetInt64Value(fuzzKey, int64Value);
    int64_t result;
    attr.GetInt64Value(fuzzKey, result);
}

static void FuzzOp7(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetStringValue / GetStringValue
    Attributes attr;
    std::string strValue = GenerateFuzzString(fuzzData, SIZE_64);
    attr.SetStringValue(fuzzKey, strValue);
    std::string result;
    attr.GetStringValue(fuzzKey, result);
}

static void FuzzOp8(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetAttributesValue / GetAttributesValue
    Attributes attr;
    Attributes innerAttr;
    attr.SetAttributesValue(fuzzKey, innerAttr);
    Attributes result;
    attr.GetAttributesValue(fuzzKey, result);
}

static void FuzzOp9(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetAttributesArrayValue / GetAttributesArrayValue
    Attributes attr;
    std::vector<Attributes> attrArray;
    uint8_t arraySize = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_5);
    for (uint8_t j = 0; j < arraySize; ++j) {
        attrArray.push_back(Attributes());
    }
    attr.SetAttributesArrayValue(fuzzKey, attrArray);
    std::vector<Attributes> result;
    attr.GetAttributesArrayValue(fuzzKey, result);
}

static void FuzzOp10(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetUint64ArrayValue / GetUint64ArrayValue
    Attributes attr;
    std::vector<uint64_t> array;
    uint8_t arraySize = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_5);
    for (uint8_t j = 0; j < arraySize; ++j) {
        array.push_back(fuzzData.ConsumeIntegral<uint64_t>());
    }
    attr.SetUint64ArrayValue(fuzzKey, array);
    std::vector<uint64_t> result;
    attr.GetUint64ArrayValue(fuzzKey, result);
}

static void FuzzOp11(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetUint32ArrayValue / GetUint32ArrayValue
    Attributes attr;
    std::vector<uint32_t> array;
    uint8_t arraySize = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_5);
    for (uint8_t j = 0; j < arraySize; ++j) {
        array.push_back(fuzzData.ConsumeIntegral<uint32_t>());
    }
    attr.SetUint32ArrayValue(fuzzKey, array);
    std::vector<uint32_t> result;
    attr.GetUint32ArrayValue(fuzzKey, result);
}

static void FuzzOp12(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetInt32ArrayValue / GetInt32ArrayValue
    Attributes attr;
    std::vector<int32_t> array;
    uint8_t arraySize = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_5);
    for (uint8_t j = 0; j < arraySize; ++j) {
        array.push_back(fuzzData.ConsumeIntegral<int32_t>());
    }
    attr.SetInt32ArrayValue(fuzzKey, array);
    std::vector<int32_t> result;
    attr.GetInt32ArrayValue(fuzzKey, result);
}

static void FuzzOp13(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetUint16ArrayValue / GetUint16ArrayValue
    Attributes attr;
    std::vector<uint16_t> array;
    uint8_t arraySize = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_5);
    for (uint8_t j = 0; j < arraySize; ++j) {
        array.push_back(fuzzData.ConsumeIntegral<uint16_t>());
    }
    attr.SetUint16ArrayValue(fuzzKey, array);
    std::vector<uint16_t> result;
    attr.GetUint16ArrayValue(fuzzKey, result);
}

static void FuzzOp14(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test SetUint8ArrayValue / GetUint8ArrayValue
    Attributes attr;
    std::vector<uint8_t> array;
    uint8_t arraySize = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_5);
    for (uint8_t j = 0; j < arraySize; ++j) {
        array.push_back(fuzzData.ConsumeIntegral<uint8_t>());
    }
    attr.SetUint8ArrayValue(fuzzKey, array);
    std::vector<uint8_t> result;
    attr.GetUint8ArrayValue(fuzzKey, result);
}

static void FuzzOp15(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    (void)fuzzKey;
    // Test Serialize
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    std::vector<uint8_t> serialized = attr.Serialize();
    (void)serialized;
}

static void FuzzOp16(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    (void)fuzzKey;
    // Test GetKeys
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto keys = attr.GetKeys();
    (void)keys;
}

static void FuzzOp17(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    // Test HasAttribute
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    bool has = attr.HasAttribute(fuzzKey);
    (void)has;
}

static void FuzzOp18(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    (void)fuzzKey;
    // Test copy constructor
    Attributes attr1 = GenerateFuzzAttributes(fuzzData);
    Attributes attr2(attr1);
    (void)attr2;
}

static void FuzzOp19(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    (void)fuzzKey;
    // Test copy assignment
    Attributes attr1 = GenerateFuzzAttributes(fuzzData);
    Attributes attr2 = attr1;
    (void)attr2;
}

static void FuzzOp20(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    (void)fuzzKey;
    // Test move constructor
    Attributes attr1 = GenerateFuzzAttributes(fuzzData);
    Attributes attr2(std::move(attr1));
    (void)attr2;
}

static void FuzzOp21(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    (void)fuzzKey;
    // Test move assignment
    Attributes attr1 = GenerateFuzzAttributes(fuzzData);
    Attributes attr2 = std::move(attr1);
    (void)attr2;
}

static void FuzzOp22(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    (void)fuzzKey;
    // Test constructor with raw data
    size_t leftRange = 0;
    size_t rightRange = SIZE_1024;
    std::vector<uint8_t> rawData =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(leftRange, rightRange));
    Attributes attr(rawData);
    (void)attr;
}

static void FuzzOp23(FuzzedDataProvider &fuzzData, Attributes::AttributeKey fuzzKey)
{
    (void)fuzzData;
    (void)fuzzKey;
    // Test default constructor
    Attributes attr;
    (void)attr;
}

static const CdaAttributesFuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3, FuzzOp4, FuzzOp5, FuzzOp6,
    FuzzOp7, FuzzOp8, FuzzOp9, FuzzOp10, FuzzOp11, FuzzOp12, FuzzOp13, FuzzOp14, FuzzOp15, FuzzOp16, FuzzOp17, FuzzOp18,
    FuzzOp19, FuzzOp20, FuzzOp21, FuzzOp22, FuzzOp23 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(CdaAttributesFuzzFunction);

void FuzzAttributes(FuzzedDataProvider &fuzzData)
{
    Attributes::AttributeKey fuzzKey = static_cast<Attributes::AttributeKey>(fuzzData.ConsumeIntegral<uint32_t>());

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](fuzzData, fuzzKey);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData, fuzzKey);
    }

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzAttributes)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
