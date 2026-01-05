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

#include "companion_delegate_auth_callback.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Helper function to convert local Attributes to UserAuth::Attributes
static UserAuth::Attributes ConvertToUserAuthAttributes(const Attributes &attr)
{
    std::vector<uint8_t> data = attr.Serialize();
    return UserAuth::Attributes(data);
}

using FuzzFunction = void (*)(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &);

static void FuzzOp0(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &fuzzData)
{
    // Test OnAcquireInfo
    int32_t module = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t acquireInfo = fuzzData.ConsumeIntegral<uint32_t>();
    Attributes extraInfo = GenerateFuzzAttributes(fuzzData);
    authCallback->OnAcquireInfo(module, acquireInfo, ConvertToUserAuthAttributes(extraInfo));
}

static void FuzzOp1(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &fuzzData)
{
    // Test OnResult
    int32_t result = fuzzData.ConsumeIntegral<int32_t>();
    Attributes extraInfo = GenerateFuzzAttributes(fuzzData);
    authCallback->OnResult(result, ConvertToUserAuthAttributes(extraInfo));
}

static void FuzzOp2(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &fuzzData)
{
    // Test with nullptr callback
    CompanionDelegateAuthCallback::ResultCallback emptyCallback = nullptr;
    auto authCallbackWithNull = std::make_shared<CompanionDelegateAuthCallback>(std::move(emptyCallback));
    if (authCallbackWithNull) {
        int32_t result = fuzzData.ConsumeIntegral<int32_t>();
        Attributes extraInfo = GenerateFuzzAttributes(fuzzData);
        authCallbackWithNull->OnResult(result, ConvertToUserAuthAttributes(extraInfo));
    }
    // Also test the normal callback
    (void)authCallback;
}

// Test OnAcquireInfo with extreme module values
static void FuzzOp3(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &fuzzData)
{
    int32_t module = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t acquireInfo = fuzzData.ConsumeIntegral<uint32_t>();
    Attributes extraInfo = GenerateFuzzAttributes(fuzzData);
    authCallback->OnAcquireInfo(module, acquireInfo, ConvertToUserAuthAttributes(extraInfo));
    // Call again with same module but different acquireInfo
    authCallback->OnAcquireInfo(module, acquireInfo + 1, ConvertToUserAuthAttributes(extraInfo));
}

// Test OnResult with various result codes
static void FuzzOp4(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &fuzzData)
{
    // Test with success and failure codes
    std::vector<int32_t> testResults = { 0, // SUCCESS
        1,                                  // GENERAL_ERROR
        -1,                                 // Negative error code
        999999,                             // Large positive value
        fuzzData.ConsumeIntegral<int32_t>() };

    for (int32_t result : testResults) {
        Attributes extraInfo = GenerateFuzzAttributes(fuzzData);
        authCallback->OnResult(result, ConvertToUserAuthAttributes(extraInfo));
    }
}

// Test OnAcquireInfo with empty extraInfo
static void FuzzOp5(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    int32_t module = 100;
    uint32_t acquireInfo = 1;
    Attributes emptyExtraInfo;
    authCallback->OnAcquireInfo(module, acquireInfo, ConvertToUserAuthAttributes(emptyExtraInfo));
}

// Test OnResult with empty extraInfo
static void FuzzOp6(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    int32_t result = 0;
    Attributes emptyExtraInfo;
    authCallback->OnResult(result, ConvertToUserAuthAttributes(emptyExtraInfo));
}

// Test OnAcquireInfo multiple times with increasing acquireInfo
static void FuzzOp7(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &fuzzData)
{
    int32_t module = fuzzData.ConsumeIntegral<int32_t>();
    Attributes extraInfo = GenerateFuzzAttributes(fuzzData);
    uint32_t num = 10;
    for (uint32_t i = 0; i < num; ++i) {
        authCallback->OnAcquireInfo(module, i, ConvertToUserAuthAttributes(extraInfo));
    }
}

// Test OnResult with different extraInfo sizes
static void FuzzOp8(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &fuzzData)
{
    int num = 5;
    int32_t result = fuzzData.ConsumeIntegral<int32_t>();
    for (int i = 0; i < num; ++i) {
        Attributes extraInfo = GenerateFuzzAttributes(fuzzData);
        authCallback->OnResult(result, ConvertToUserAuthAttributes(extraInfo));
    }
}

// Test combination: OnAcquireInfo followed by OnResult
static void FuzzOp9(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &fuzzData)
{
    int32_t module = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t acquireInfo = fuzzData.ConsumeIntegral<uint32_t>();
    int32_t result = fuzzData.ConsumeIntegral<int32_t>();
    Attributes extraInfo = GenerateFuzzAttributes(fuzzData);

    authCallback->OnAcquireInfo(module, acquireInfo, ConvertToUserAuthAttributes(extraInfo));
    authCallback->OnResult(result, ConvertToUserAuthAttributes(extraInfo));
}

// Test OnAcquireInfo with boundary module values
static void FuzzOp10(std::shared_ptr<CompanionDelegateAuthCallback> &authCallback, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    uint32_t acquireInfo = 1;
    Attributes extraInfo = GenerateFuzzAttributes(fuzzData);

    std::vector<int32_t> boundaryModules = { INT32_MIN, INT32_MAX, 0, 100, -100 };

    for (int32_t module : boundaryModules) {
        authCallback->OnAcquireInfo(module, acquireInfo, ConvertToUserAuthAttributes(extraInfo));
    }
}

static const FuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3, FuzzOp4, FuzzOp5, FuzzOp6, FuzzOp7,
    FuzzOp8, FuzzOp9, FuzzOp10 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzCompanionDelegateAuthCallback(FuzzedDataProvider &fuzzData)
{
    // Create a callback for testing
    CompanionDelegateAuthCallback::ResultCallback callback = [](ResultCode result,
                                                                 const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };
    auto authCallback = std::make_shared<CompanionDelegateAuthCallback>(std::move(callback));
    if (!authCallback) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);

    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](authCallback, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
