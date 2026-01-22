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

#include "companion_device_auth_ffi_util.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FfiUtilFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzDecodeDeviceKey(FuzzedDataProvider &fuzzData)
{
    DeviceKeyFfi ffi;
    ffi.deviceIdType = fuzzData.ConsumeIntegral<uint32_t>();
    ffi.deviceId.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL64);
    for (uint32_t i = 0; i < ffi.deviceId.len && i < TEST_VAL64; ++i) {
        ffi.deviceId.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }
    ffi.userId = fuzzData.ConsumeIntegral<uint32_t>();

    DeviceKey key;
    (void)DecodeDeviceKey(ffi, key);
}

static void FuzzEncodeDeviceKey(FuzzedDataProvider &fuzzData)
{
    DeviceKey key = GenerateFuzzDeviceKey(fuzzData);
    DeviceKeyFfi ffi;
    (void)EncodeDeviceKey(key, ffi);
}

static void FuzzDecodeEvent(FuzzedDataProvider &fuzzData)
{
    EventFfi ffi;
    ffi.time = fuzzData.ConsumeIntegral<uint64_t>();
    ffi.fileName.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL64);
    for (uint32_t i = 0; i < ffi.fileName.len && i < TEST_VAL64; ++i) {
        ffi.fileName.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }
    ffi.lineNumber = fuzzData.ConsumeIntegral<uint32_t>();
    ffi.eventType = fuzzData.ConsumeIntegral<int32_t>();
    ffi.eventInfo.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL256);
    for (uint32_t i = 0; i < ffi.eventInfo.len && i < TEST_VAL256; ++i) {
        ffi.eventInfo.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    Event event;
    (void)DecodeEvent(ffi, event);
}

static void FuzzDecodeCommonOutput(FuzzedDataProvider &fuzzData)
{
    CommonOutputFfi ffi;
    ffi.result = fuzzData.ConsumeIntegral<int32_t>();
    ffi.hasFatalError = fuzzData.ConsumeBool();
    uint32_t leftRange = 0;
    uint32_t rightRange = 10;
    ffi.events.len = fuzzData.ConsumeIntegralInRange<uint32_t>(leftRange, rightRange);

    for (uint32_t i = 0; i < ffi.events.len; ++i) {
        ffi.events.data[i].fileName.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL64);
        for (uint32_t j = 0; j < ffi.events.data[i].fileName.len && j < TEST_VAL64; ++j) {
            ffi.events.data[i].fileName.data[j] = fuzzData.ConsumeIntegral<uint8_t>();
        }
        ffi.events.data[i].lineNumber = fuzzData.ConsumeIntegral<uint32_t>();
        ffi.events.data[i].eventType = fuzzData.ConsumeIntegral<int32_t>();
    }

    CommonOutput output;
    (void)DecodeCommonOutput(ffi, output);
}

static const FfiUtilFuzzFunction g_fuzzFuncs[] = {
    FuzzDecodeDeviceKey,
    FuzzEncodeDeviceKey,
    FuzzDecodeEvent,
    FuzzDecodeCommonOutput,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FfiUtilFuzzFunction);

void FuzzFfiUtil(FuzzedDataProvider &fuzzData)
{
    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData);
    }

    EnsureAllTaskExecuted();
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(FfiUtil)

} // namespace UserIam
} // namespace OHOS
