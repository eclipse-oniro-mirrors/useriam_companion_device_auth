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
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "host_obtain_token_request.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using HostObtainTokenRequestFuzzFunction = void (*)(std::shared_ptr<HostObtainTokenRequest> &request,
    FuzzedDataProvider &fuzzData);

static void FuzzGetMaxConcurrency(std::shared_ptr<HostObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetMaxConcurrency();
}

static void FuzzShouldCancelOnNewRequest(std::shared_ptr<HostObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    RequestType newType = static_cast<RequestType>(fuzzData.ConsumeIntegral<uint32_t>());
    std::optional<DeviceKey> newPeer;
    if (fuzzData.ConsumeBool()) {
        newPeer = GenerateFuzzDeviceKey(fuzzData);
    }
    uint32_t count = fuzzData.ConsumeIntegral<uint32_t>();
    (void)request->ShouldCancelOnNewRequest(newType, newPeer, count);
}

static void FuzzOnStart(std::shared_ptr<HostObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ErrorGuard errorGuard([](ResultCode result) { (void)result; });
    (void)request->OnStart(errorGuard);
}

static void FuzzCompleteWithError(std::shared_ptr<HostObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    request->CompleteWithError(result);
}

static void FuzzCompleteWithSuccess(std::shared_ptr<HostObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->CompleteWithSuccess();
}

static void FuzzGetWeakPtr(std::shared_ptr<HostObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetWeakPtr();
}

static void FuzzParsePreObtainTokenRequest(std::shared_ptr<HostObtainTokenRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ErrorGuard errorGuard([](ResultCode result) { (void)result; });
    (void)request->ParsePreObtainTokenRequest(errorGuard);
}

static void FuzzProcessPreObtainToken(std::shared_ptr<HostObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::vector<uint8_t> preObtainTokenReplyData;
    (void)request->ProcessPreObtainToken(preObtainTokenReplyData);
}

static void FuzzSendPreObtainTokenReply(std::shared_ptr<HostObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    uint32_t replySize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> preObtainTokenReplyData = fuzzData.ConsumeBytes<uint8_t>(replySize);
    request->SendPreObtainTokenReply(result, preObtainTokenReplyData);
}

static void FuzzHandlePeerDeviceStatusChanged(std::shared_ptr<HostObtainTokenRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    uint8_t statusCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_DEVICE_STATUS_COUNT);
    std::vector<DeviceStatus> deviceStatusList = GenerateFuzzDeviceStatusList(fuzzData, statusCount);
    request->HandlePeerDeviceStatusChanged(deviceStatusList);
}

static const HostObtainTokenRequestFuzzFunction g_fuzzFuncs[] = {
    FuzzGetMaxConcurrency,
    FuzzShouldCancelOnNewRequest,
    FuzzOnStart,
    FuzzCompleteWithError,
    FuzzCompleteWithSuccess,
    FuzzGetWeakPtr,
    FuzzParsePreObtainTokenRequest,
    FuzzProcessPreObtainToken,
    FuzzSendPreObtainTokenReply,
    FuzzHandlePeerDeviceStatusChanged,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(HostObtainTokenRequestFuzzFunction);

void FuzzHostObtainTokenRequest(FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, 64);
    Attributes request = GenerateFuzzAttributes(fuzzData);
    OnMessageReply replyCallback = [](const Attributes &reply) { (void)reply; };
    DeviceKey companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);

    auto obtainTokenRequest =
        std::make_shared<HostObtainTokenRequest>(connectionName, request, std::move(replyCallback), companionDeviceKey);
    if (!obtainTokenRequest) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](obtainTokenRequest, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](obtainTokenRequest, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzHostObtainTokenRequest)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
