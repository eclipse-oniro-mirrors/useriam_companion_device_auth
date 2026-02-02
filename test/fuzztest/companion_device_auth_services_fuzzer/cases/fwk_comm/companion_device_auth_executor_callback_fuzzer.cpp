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
#include <functional>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "common_defines.h"
#include "companion_device_auth_executor_callback.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "fwk_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

constexpr int32_t INT32_5 = 5;
constexpr int32_t INT32_100 = 100;

class MockFrameworkCallback : public FwkIExecuteCallback {
public:
    void OnResult(FwkResultCode result, const std::vector<uint8_t> &extraInfo) override
    {
        (void)result;
        (void)extraInfo;
    }

    void OnResult(ResultCode result) override
    {
        (void)result;
    }

    void OnAcquireInfo(int32_t acquire, const std::vector<uint8_t> &extraInfo) override
    {
        (void)acquire;
        (void)extraInfo;
    }

    void OnMessage(int destRole, const std::vector<uint8_t> &msg) override
    {
        (void)destRole;
        (void)msg;
    }
};

using CompanionDeviceAuthExecutorCallbackFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzCallbackWithResult(FuzzedDataProvider &fuzzData)
{
    auto frameworkCallback = std::make_shared<MockFrameworkCallback>();
    CompanionDeviceAuthExecutorCallback callback(frameworkCallback);

    ResultCode resultCode = GenerateFuzzResultCode(fuzzData);
    uint32_t extraInfoSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> extraInfo = fuzzData.ConsumeBytes<uint8_t>(extraInfoSize);

    callback(resultCode, extraInfo);
}

static void FuzzCallbackWithNullFramework(FuzzedDataProvider &fuzzData)
{
    CompanionDeviceAuthExecutorCallback callback(nullptr);

    ResultCode resultCode = GenerateFuzzResultCode(fuzzData);
    uint32_t extraInfoSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> extraInfo = fuzzData.ConsumeBytes<uint8_t>(extraInfoSize);

    callback(resultCode, extraInfo);
}

static void FuzzCallbackWithEmptyExtraInfo(FuzzedDataProvider &fuzzData)
{
    auto frameworkCallback = std::make_shared<MockFrameworkCallback>();
    CompanionDeviceAuthExecutorCallback callback(frameworkCallback);

    ResultCode resultCode = GenerateFuzzResultCode(fuzzData);
    std::vector<uint8_t> extraInfo;

    callback(resultCode, extraInfo);
}

static void FuzzCallbackWithLargeExtraInfo(FuzzedDataProvider &fuzzData)
{
    auto frameworkCallback = std::make_shared<MockFrameworkCallback>();
    CompanionDeviceAuthExecutorCallback callback(frameworkCallback);

    ResultCode resultCode = GenerateFuzzResultCode(fuzzData);
    std::vector<uint8_t> extraInfo(FUZZ_MAX_MESSAGE_LENGTH);

    callback(resultCode, extraInfo);
}

static void FuzzMultipleCallbackInvocations(FuzzedDataProvider &fuzzData)
{
    auto frameworkCallback = std::make_shared<MockFrameworkCallback>();
    CompanionDeviceAuthExecutorCallback callback(frameworkCallback);

    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_5);
    for (uint8_t i = 0; i < count; ++i) {
        ResultCode resultCode = GenerateFuzzResultCode(fuzzData);
        std::vector<uint8_t> extraInfo =
            fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
        callback(resultCode, extraInfo);
    }
}

static const CompanionDeviceAuthExecutorCallbackFuzzFunction g_fuzzFuncs[] = {
    FuzzCallbackWithResult,
    FuzzCallbackWithNullFramework,
    FuzzCallbackWithEmptyExtraInfo,
    FuzzCallbackWithLargeExtraInfo,
    FuzzMultipleCallbackInvocations,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(CompanionDeviceAuthExecutorCallbackFuzzFunction);

void FuzzCompanionDeviceAuthExecutorCallback(FuzzedDataProvider &fuzzData)
{
    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = INT32_100;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzCompanionDeviceAuthExecutorCallback)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
