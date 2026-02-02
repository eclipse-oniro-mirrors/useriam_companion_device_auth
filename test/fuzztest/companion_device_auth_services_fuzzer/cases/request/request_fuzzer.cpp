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
#include "request_factory_impl.h"
#include "request_manager_impl.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using RequestFuzzFunction = void (*)(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData);

static void FuzzCreateRequestManager(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)manager;
    auto newManager = RequestManagerImpl::Create();
    (void)newManager;
}

static void FuzzGetRequest(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    RequestId requestId = fuzzData.ConsumeIntegral<RequestId>();
    auto request = manager->Get(requestId);
    (void)request;
}

static void FuzzCancelByRequestId(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    RequestId requestId = fuzzData.ConsumeIntegral<RequestId>();
    bool result = manager->Cancel(requestId);
    (void)result;
}

static void FuzzCancelByScheduleId(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    bool result = manager->CancelRequestByScheduleId(scheduleId);
    (void)result;
}

static void FuzzCancelAll(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    manager->CancelAll();
}

static void FuzzRemoveRequest(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    RequestId requestId = fuzzData.ConsumeIntegral<RequestId>();
    manager->Remove(requestId);
}

static void FuzzGenerateRequestId(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)manager;
    RequestId requestId = fuzzData.ConsumeIntegral<RequestId>();
    (void)requestId;
}

static void FuzzGenerateScheduleId(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)manager;
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    (void)scheduleId;
}

static void FuzzGenerateDeviceKey(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)manager;
    auto deviceKey = GenerateFuzzDeviceKey(fuzzData);
    (void)deviceKey;
}

static void FuzzGenerateResultCode(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)manager;
    auto resultCode = GenerateFuzzResultCode(fuzzData);
    (void)resultCode;
}

static void FuzzGenerateAttributes(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)manager;
    Attributes attrs = GenerateFuzzAttributes(fuzzData);
    (void)attrs;
}

static void FuzzGenerateRequestType(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)manager;
    RequestType requestType = static_cast<RequestType>(fuzzData.ConsumeIntegral<int32_t>());
    (void)requestType;
}

static void FuzzGenerateDeviceStatus(std::shared_ptr<RequestManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)manager;
    DeviceStatus status = GenerateFuzzDeviceStatus(fuzzData);
    (void)status;
}

static const RequestFuzzFunction g_fuzzFuncs[] = {
    FuzzCreateRequestManager,
    FuzzGetRequest,
    FuzzCancelByRequestId,
    FuzzCancelByScheduleId,
    FuzzCancelAll,
    FuzzRemoveRequest,
    FuzzGenerateRequestId,
    FuzzGenerateScheduleId,
    FuzzGenerateDeviceKey,
    FuzzGenerateResultCode,
    FuzzGenerateAttributes,
    FuzzGenerateRequestType,
    FuzzGenerateDeviceStatus,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(RequestFuzzFunction);

void FuzzRequest(FuzzedDataProvider &fuzzData)
{
    auto manager = RequestManagerImpl::Create();
    if (!manager) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](manager, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](manager, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzRequest)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
