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

#include "companion_obtain_token_request.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "obtain_token_message.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using CompanionObtainTokenRequestFuzzFunction = void (*)(std::shared_ptr<CompanionObtainTokenRequest> &request,
    FuzzedDataProvider &fuzzData);

static void FuzzGetMaxConcurrency(std::shared_ptr<CompanionObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetMaxConcurrency();
}

static void FuzzShouldCancelOnNewRequest(std::shared_ptr<CompanionObtainTokenRequest> &request,
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

static void FuzzOnStart(std::shared_ptr<CompanionObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ErrorGuard errorGuard([](ResultCode result) { (void)result; });
    (void)request->OnStart(errorGuard);
}

static void FuzzOnConnected(std::shared_ptr<CompanionObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->OnConnected();
}

static void FuzzCompleteWithError(std::shared_ptr<CompanionObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    request->CompleteWithError(result);
}

static void FuzzCompleteWithSuccess(std::shared_ptr<CompanionObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->CompleteWithSuccess();
}

static void FuzzGetWeakPtr(std::shared_ptr<CompanionObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetWeakPtr();
}

static void FuzzGetRequestInfo(std::shared_ptr<CompanionObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetRequestType();
    (void)request->GetScheduleId();
}

static void FuzzGetPeerInfo(std::shared_ptr<CompanionObtainTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetPeerDeviceKey();
    (void)request->GetDescription();
}

static void FuzzSendPreObtainTokenRequest(std::shared_ptr<CompanionObtainTokenRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->SendPreObtainTokenRequest();
}

static void FuzzHandlePreObtainTokenReply(std::shared_ptr<CompanionObtainTokenRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    Attributes reply = GenerateFuzzAttributes(fuzzData);
    request->HandlePreObtainTokenReply(reply);
}

static void FuzzCompanionBeginObtainToken(std::shared_ptr<CompanionObtainTokenRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    PreObtainTokenReply reply = {};
    reply.result = fuzzData.ConsumeIntegral<int32_t>();
    reply.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    (void)request->CompanionBeginObtainToken(reply);
}

static void FuzzSendObtainTokenRequest(std::shared_ptr<CompanionObtainTokenRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::vector<uint8_t> obtainTokenRequest =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    (void)request->SendObtainTokenRequest(obtainTokenRequest);
}

static void FuzzHandleObtainTokenReply(std::shared_ptr<CompanionObtainTokenRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    Attributes reply = GenerateFuzzAttributes(fuzzData);
    request->HandleObtainTokenReply(reply);
}

static void FuzzCompanionEndObtainToken(std::shared_ptr<CompanionObtainTokenRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ObtainTokenReply obtainTokenReply = {};
    obtainTokenReply.result = fuzzData.ConsumeIntegral<int32_t>();
    obtainTokenReply.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    RequestId requestId = fuzzData.ConsumeIntegral<uint64_t>();
    (void)request->CompanionEndObtainToken(obtainTokenReply, requestId);
}

static const CompanionObtainTokenRequestFuzzFunction g_fuzzFuncs[] = {
    FuzzGetMaxConcurrency,
    FuzzShouldCancelOnNewRequest,
    FuzzOnStart,
    FuzzOnConnected,
    FuzzCompleteWithError,
    FuzzCompleteWithSuccess,
    FuzzGetWeakPtr,
    FuzzGetRequestInfo,
    FuzzGetPeerInfo,
    FuzzSendPreObtainTokenRequest,
    FuzzHandlePreObtainTokenReply,
    FuzzCompanionBeginObtainToken,
    FuzzSendObtainTokenRequest,
    FuzzHandleObtainTokenReply,
    FuzzCompanionEndObtainToken,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(CompanionObtainTokenRequestFuzzFunction);

void FuzzCompanionObtainTokenRequest(FuzzedDataProvider &fuzzData)
{
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    std::vector<uint8_t> fwkUnlockMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    auto obtainTokenRequest = std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
    if (!obtainTokenRequest) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](obtainTokenRequest, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(CompanionObtainTokenRequest)

} // namespace UserIam
} // namespace OHOS
