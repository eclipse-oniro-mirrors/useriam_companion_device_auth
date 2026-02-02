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

#include "companion_delegate_auth_request.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

constexpr uint32_t SIZE_64 = 64;

using CompanionDelegateAuthRequestFuzzFunction = void (*)(std::shared_ptr<CompanionDelegateAuthRequest> &request,
    FuzzedDataProvider &fuzzData);

static void FuzzCompanionBeginDelegateAuth(std::shared_ptr<CompanionDelegateAuthRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->CompanionBeginDelegateAuth();
}

static void FuzzGetMaxConcurrency(std::shared_ptr<CompanionDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetMaxConcurrency();
}

static void FuzzShouldCancelOnNewRequest(std::shared_ptr<CompanionDelegateAuthRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    RequestType newType = static_cast<RequestType>(fuzzData.ConsumeIntegral<uint32_t>());
    std::optional<DeviceKey> newPeer;
    if (fuzzData.ConsumeBool()) {
        newPeer = GenerateFuzzDeviceKey(fuzzData);
    }
    uint32_t count = fuzzData.ConsumeIntegral<uint32_t>();
    (void)request->ShouldCancelOnNewRequest(newType, newPeer, count);
}

static void FuzzOnStart(std::shared_ptr<CompanionDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ErrorGuard errorGuard([](ResultCode result) { (void)result; });
    (void)request->OnStart(errorGuard);
}

static void FuzzCompleteWithError(std::shared_ptr<CompanionDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    request->CompleteWithError(result);
}

static void FuzzCompleteWithSuccess(std::shared_ptr<CompanionDelegateAuthRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->CompleteWithSuccess();
}

static void FuzzGetWeakPtr(std::shared_ptr<CompanionDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetWeakPtr();
}

static void FuzzGetRequestInfo(std::shared_ptr<CompanionDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetRequestType();
    (void)request->GetScheduleId();
}

static void FuzzGetPeerInfo(std::shared_ptr<CompanionDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetPeerDeviceKey();
    (void)request->GetDescription();
}

static void FuzzGetRequestId(std::shared_ptr<CompanionDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetRequestId();
}

static const CompanionDelegateAuthRequestFuzzFunction g_fuzzFuncs[] = {
    FuzzCompanionBeginDelegateAuth,
    FuzzGetMaxConcurrency,
    FuzzShouldCancelOnNewRequest,
    FuzzOnStart,
    FuzzCompleteWithError,
    FuzzCompleteWithSuccess,
    FuzzGetWeakPtr,
    FuzzGetRequestInfo,
    FuzzGetPeerInfo,
    FuzzGetRequestId,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(CompanionDelegateAuthRequestFuzzFunction);

void FuzzCompanionDelegateAuthRequest(FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    int32_t companionUserId = fuzzData.ConsumeIntegral<int32_t>();
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    std::vector<uint8_t> startDelegateAuthRequest =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    auto delegateAuthRequest = std::make_shared<CompanionDelegateAuthRequest>(connectionName, companionUserId,
        hostDeviceKey, startDelegateAuthRequest);
    if (!delegateAuthRequest) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](delegateAuthRequest, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](delegateAuthRequest, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzCompanionDelegateAuthRequest)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
