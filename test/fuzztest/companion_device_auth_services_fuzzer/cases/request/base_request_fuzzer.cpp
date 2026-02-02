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
#include "fuzz_registry.h"
#include "host_add_companion_request.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr int32_t INT32_100 = 100;
}

using BaseRequestFuzzFunction = void (*)(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData);

static void FuzzGetRequestType(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    RequestType type = request->GetRequestType();
    (void)type;
}

static void FuzzGetDescription(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    const char *desc = request->GetDescription();
    (void)desc;
}

static void FuzzGetRequestId(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    RequestId id = request->GetRequestId();
    (void)id;
}

static void FuzzGetScheduleId(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ScheduleId id = request->GetScheduleId();
    (void)id;
}

static void FuzzGetPeerDeviceKey(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto key = request->GetPeerDeviceKey();
    (void)key;
}

static void FuzzGetMaxConcurrency(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    uint32_t max = request->GetMaxConcurrency();
    (void)max;
}

static void FuzzShouldCancelOnNewRequest(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData)
{
    RequestType newType = static_cast<RequestType>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, INT32_100));
    std::optional<DeviceKey> newPeer;
    if (fuzzData.ConsumeBool()) {
        newPeer = GenerateFuzzDeviceKey(fuzzData);
    }
    uint32_t count = fuzzData.ConsumeIntegral<uint32_t>();
    bool shouldCancel = request->ShouldCancelOnNewRequest(newType, newPeer, count);
    (void)shouldCancel;
}

static void FuzzStart(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->Start();
}

static void FuzzCancel(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    bool cancelled = request->Cancel(result);
    (void)cancelled;
}

static void FuzzCreateScheduleId(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)request;
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    (void)scheduleId;
}

static void FuzzCreateTimeoutMs(std::shared_ptr<IRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)request;
    uint32_t timeoutMs = fuzzData.ConsumeIntegral<uint32_t>();
    (void)timeoutMs;
}

static const BaseRequestFuzzFunction g_fuzzFuncs[] = {
    FuzzGetRequestType,
    FuzzGetDescription,
    FuzzGetRequestId,
    FuzzGetScheduleId,
    FuzzGetPeerDeviceKey,
    FuzzGetMaxConcurrency,
    FuzzShouldCancelOnNewRequest,
    FuzzStart,
    FuzzCancel,
    FuzzCreateScheduleId,
    FuzzCreateTimeoutMs,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(BaseRequestFuzzFunction);

void FuzzBaseRequest(FuzzedDataProvider &fuzzData)
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

    std::shared_ptr<IRequest> baseRequest = request;

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](baseRequest, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](baseRequest, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzBaseRequest)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
