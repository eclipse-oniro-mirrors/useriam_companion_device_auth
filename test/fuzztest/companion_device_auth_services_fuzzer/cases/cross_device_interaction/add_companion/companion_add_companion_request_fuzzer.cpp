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

#include "companion_add_companion_request.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using CompanionAddCompanionRequestFuzzFunction = void (*)(std::shared_ptr<CompanionAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData);

static void FuzzGetMaxConcurrency(std::shared_ptr<CompanionAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetMaxConcurrency();
}

static void FuzzShouldCancelOnNewRequest(std::shared_ptr<CompanionAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    RequestType newRequestType = static_cast<RequestType>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, 20));
    std::optional<DeviceKey> newPeerDevice;
    if (fuzzData.ConsumeBool()) {
        newPeerDevice = GenerateFuzzDeviceKey(fuzzData);
    }
    uint32_t subsequentSameTypeCount = fuzzData.ConsumeIntegral<uint32_t>();
    (void)request->ShouldCancelOnNewRequest(newRequestType, newPeerDevice, subsequentSameTypeCount);
}

static void FuzzStart(std::shared_ptr<CompanionAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->Start();
}

static void FuzzCancel(std::shared_ptr<CompanionAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode resultCode = GenerateFuzzResultCode(fuzzData);
    (void)request->Cancel(resultCode);
}

static void FuzzGetRequestType(std::shared_ptr<CompanionAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetRequestType();
}

static void FuzzGetDescription(std::shared_ptr<CompanionAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetDescription();
}

static void FuzzGetRequestId(std::shared_ptr<CompanionAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetRequestId();
}

static void FuzzGetScheduleId(std::shared_ptr<CompanionAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetScheduleId();
}

static void FuzzGetPeerDeviceKey(std::shared_ptr<CompanionAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetPeerDeviceKey();
}

static void FuzzCompleteWithError(std::shared_ptr<CompanionAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    request->CompleteWithError(result);
}

static void FuzzCompleteWithSuccess(std::shared_ptr<CompanionAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->CompleteWithSuccess();
}

static void FuzzOnStart(std::shared_ptr<CompanionAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ErrorGuard errorGuard([](ResultCode code) { (void)code; });
    (void)request->OnStart(errorGuard);
}

static void FuzzCompanionInitKeyNegotiation(std::shared_ptr<CompanionAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    // Simplified implementation - just create a default request
    InitKeyNegotiationRequest keyNegotiationRequest = {};
    std::vector<uint8_t> initKeyNegotiationReply =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    (void)request->CompanionInitKeyNegotiation(keyNegotiationRequest, initKeyNegotiationReply);
}

static void FuzzSendInitKeyNegotiationReply(std::shared_ptr<CompanionAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    std::vector<uint8_t> initKeyNegotiationReply =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    (void)request->SendInitKeyNegotiationReply(result, initKeyNegotiationReply);
}

static void FuzzHandleBeginAddCompanion(std::shared_ptr<CompanionAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    Attributes attrInput = GenerateFuzzAttributes(fuzzData);
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    request->HandleBeginAddCompanion(attrInput, onMessageReply);
}

static void FuzzHandleEndAddCompanion(std::shared_ptr<CompanionAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    Attributes attrInput = GenerateFuzzAttributes(fuzzData);
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    request->HandleEndAddCompanion(attrInput, onMessageReply);
}

static const CompanionAddCompanionRequestFuzzFunction g_fuzzFuncs[] = {
    FuzzGetMaxConcurrency,
    FuzzShouldCancelOnNewRequest,
    FuzzStart,
    FuzzCancel,
    FuzzGetRequestType,
    FuzzGetDescription,
    FuzzGetRequestId,
    FuzzGetScheduleId,
    FuzzGetPeerDeviceKey,
    FuzzCompleteWithError,
    FuzzCompleteWithSuccess,
    FuzzOnStart,
    FuzzCompanionInitKeyNegotiation,
    FuzzSendInitKeyNegotiationReply,
    FuzzHandleBeginAddCompanion,
    FuzzHandleEndAddCompanion,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(CompanionAddCompanionRequestFuzzFunction);

void FuzzCompanionAddCompanionRequest(FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, 64);
    Attributes request = GenerateFuzzAttributes(fuzzData);

    OnMessageReply firstReply = [](const Attributes &reply) { (void)reply; };
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);

    auto inboundRequest =
        std::make_shared<CompanionAddCompanionRequest>(connectionName, request, std::move(firstReply), hostDeviceKey);
    if (!inboundRequest) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);

    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](inboundRequest, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(CompanionAddCompanionRequest)

} // namespace UserIam
} // namespace OHOS
