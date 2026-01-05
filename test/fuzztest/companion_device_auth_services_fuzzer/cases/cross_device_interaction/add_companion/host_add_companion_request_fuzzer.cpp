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

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "host_add_companion_request.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(std::shared_ptr<HostAddCompanionRequest> &request, FuzzedDataProvider &fuzzData);

static void FuzzGetMaxConcurrency(std::shared_ptr<HostAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetMaxConcurrency();
}

static void FuzzShouldCancelOnNewRequest(std::shared_ptr<HostAddCompanionRequest> &request,
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

static void FuzzOnStart(std::shared_ptr<HostAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ErrorGuard errorGuard([](ResultCode result) { (void)result; });
    (void)request->OnStart(errorGuard);
}

static void FuzzOnConnected(std::shared_ptr<HostAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->OnConnected();
}

static void FuzzCompleteWithError(std::shared_ptr<HostAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    request->CompleteWithError(result);
}

static void FuzzCompleteWithSuccess(std::shared_ptr<HostAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->CompleteWithSuccess();
}

static void FuzzGetWeakPtr(std::shared_ptr<HostAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetWeakPtr();
}

static void FuzzHandleDeviceSelectResult(std::shared_ptr<HostAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    uint8_t deviceCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_DEVICE_KEY_COUNT);
    std::vector<DeviceKey> selectedDevices;
    for (uint8_t i = 0; i < deviceCount; ++i) {
        selectedDevices.push_back(GenerateFuzzDeviceKey(fuzzData));
    }
    request->HandleDeviceSelectResult(selectedDevices);
}

static void FuzzHandleInitKeyNegotiationReply(std::shared_ptr<HostAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    Attributes reply = GenerateFuzzAttributes(fuzzData);
    request->HandleInitKeyNegotiationReply(reply);
}

static void FuzzHandleBeginAddHostBindingReply(std::shared_ptr<HostAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    Attributes reply = GenerateFuzzAttributes(fuzzData);
    request->HandleBeginAddHostBindingReply(reply);
}

static void FuzzHandleEndAddHostBindingReply(std::shared_ptr<HostAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    Attributes reply = GenerateFuzzAttributes(fuzzData);
    request->HandleEndAddHostBindingReply(reply);
}

static void FuzzSendEndAddHostBindingMsg(std::shared_ptr<HostAddCompanionRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    (void)request->SendEndAddHostBindingMsg(result);
}

static void FuzzCancel(std::shared_ptr<HostAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode resultCode = GenerateFuzzResultCode(fuzzData);
    (void)request->Cancel(resultCode);
}

static void FuzzBeginAddCompanion(std::shared_ptr<HostAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    InitKeyNegotiationReply reply;
    reply.result = GenerateFuzzResultCode(fuzzData);
    reply.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    std::vector<uint8_t> addHostBindingRequest =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    ErrorGuard errorGuard([](ResultCode result) { (void)result; });
    request->BeginAddCompanion(reply, addHostBindingRequest, errorGuard);
}

static void FuzzEndAddCompanion(std::shared_ptr<HostAddCompanionRequest> &request, FuzzedDataProvider &fuzzData)
{
    BeginAddHostBindingReply reply;
    reply.result = GenerateFuzzResultCode(fuzzData);
    reply.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    request->EndAddCompanion(reply, fwkMsg);
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzGetMaxConcurrency,
    FuzzShouldCancelOnNewRequest,
    FuzzOnStart,
    FuzzOnConnected,
    FuzzCompleteWithError,
    FuzzCompleteWithSuccess,
    FuzzGetWeakPtr,
    FuzzHandleDeviceSelectResult,
    FuzzHandleInitKeyNegotiationReply,
    FuzzHandleBeginAddHostBindingReply,
    FuzzHandleEndAddHostBindingReply,
    FuzzSendEndAddHostBindingMsg,
    FuzzCancel,
    FuzzBeginAddCompanion,
    FuzzEndAddCompanion,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzHostAddCompanionRequest(FuzzedDataProvider &fuzzData)
{
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();

    FwkResultCallback callback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };

    auto request = std::make_shared<HostAddCompanionRequest>(scheduleId, fwkMsg, tokenId, std::move(callback));
    if (!request) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);

    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](request, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
