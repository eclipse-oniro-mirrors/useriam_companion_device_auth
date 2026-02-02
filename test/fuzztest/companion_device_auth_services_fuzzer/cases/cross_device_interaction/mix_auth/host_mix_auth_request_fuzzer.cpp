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

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "host_mix_auth_request.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using HostMixAuthRequestFuzzFunction = void (*)(std::shared_ptr<HostMixAuthRequest> &request,
    FuzzedDataProvider &fuzzData);

static void FuzzGetMaxConcurrency(std::shared_ptr<HostMixAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetMaxConcurrency();
}

static void FuzzShouldCancelOnNewRequest(std::shared_ptr<HostMixAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    RequestType requestType = static_cast<RequestType>(fuzzData.ConsumeIntegralInRange<uint8_t>(0, 10));
    std::optional<DeviceKey> deviceKey;
    if (fuzzData.ConsumeBool()) {
        deviceKey = GenerateFuzzDeviceKey(fuzzData);
    }
    uint32_t count = fuzzData.ConsumeIntegral<uint32_t>();
    (void)request->ShouldCancelOnNewRequest(requestType, deviceKey, count);
}

static void FuzzStart(std::shared_ptr<HostMixAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->Start();
}

static void FuzzCancel(std::shared_ptr<HostMixAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    (void)request->Cancel(result);
}

static void FuzzCompleteWithSuccess(std::shared_ptr<HostMixAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    std::vector<uint8_t> extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_FWK_MESSAGE_LENGTH));
    (void)request->CompleteWithSuccess(extraInfo);
}

static void FuzzCompleteWithError(std::shared_ptr<HostMixAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    (void)request->CompleteWithError(result);
}

static void FuzzDestroy(std::shared_ptr<HostMixAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->Destroy();
}

static void FuzzInvokeCallback(std::shared_ptr<HostMixAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    std::vector<uint8_t> extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_FWK_MESSAGE_LENGTH));
    (void)request->InvokeCallback(result, extraInfo);
}

static void FuzzGetRequestInfo(std::shared_ptr<HostMixAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetRequestType();
    (void)request->GetScheduleId();
    (void)request->GetDescription();
}

static const HostMixAuthRequestFuzzFunction g_fuzzFuncs[] = {
    FuzzGetMaxConcurrency,
    FuzzShouldCancelOnNewRequest,
    FuzzStart,
    FuzzCancel,
    FuzzCompleteWithSuccess,
    FuzzCompleteWithError,
    FuzzDestroy,
    FuzzInvokeCallback,
    FuzzGetRequestInfo,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(HostMixAuthRequestFuzzFunction);

void FuzzHostMixAuthRequest(FuzzedDataProvider &fuzzData)
{
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_FWK_MESSAGE_LENGTH));
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();

    uint8_t templateCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_CAPABILITIES_COUNT);
    std::vector<TemplateId> templateIdList;
    for (uint8_t i = 0; i < templateCount; ++i) {
        templateIdList.push_back(fuzzData.ConsumeIntegral<TemplateId>());
    }

    FwkResultCallback callback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };

    auto request =
        std::make_shared<HostMixAuthRequest>(scheduleId, fwkMsg, hostUserId, templateIdList, std::move(callback));
    if (!request) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](request, fuzzData);

        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](request, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzHostMixAuthRequest)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
