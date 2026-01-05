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

#include "companion_auth_maintain_state_change_request.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request,
    FuzzedDataProvider &fuzzData);

static void FuzzOp0(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetMaxConcurrency();
}

static void FuzzOp1(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    RequestType newRequestType = static_cast<RequestType>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, 20));
    std::optional<DeviceKey> newPeerDevice;
    if (fuzzData.ConsumeBool()) {
        newPeerDevice = GenerateFuzzDeviceKey(fuzzData);
    }
    uint32_t subsequentSameTypeCount = fuzzData.ConsumeIntegral<uint32_t>();
    (void)request->ShouldCancelOnNewRequest(newRequestType, newPeerDevice, subsequentSameTypeCount);
}

static void FuzzOp2(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->Start();
}

static void FuzzOp3(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode resultCode = GenerateFuzzResultCode(fuzzData);
    (void)request->Cancel(resultCode);
}

static void FuzzOp4(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetRequestType();
}

static void FuzzOp5(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetDescription();
}

static void FuzzOp6(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetRequestId();
}

static void FuzzOp7(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetScheduleId();
}

static void FuzzOp8(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetPeerDeviceKey();
}

static void FuzzOp9(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    request->CompleteWithError(result);
}

static void FuzzOp10(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetWeakPtr();
}

static void FuzzOp11(std::shared_ptr<CompanionAuthMaintainStateChangeRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->OnConnected();
}

static const FuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3, FuzzOp4, FuzzOp5, FuzzOp6, FuzzOp7,
    FuzzOp8, FuzzOp9, FuzzOp10, FuzzOp11 };

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzCompanionAuthMaintainStateChangeRequest(FuzzedDataProvider &fuzzData)
{
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    bool authMaintainState = fuzzData.ConsumeBool();

    auto stateChangeRequest =
        std::make_shared<CompanionAuthMaintainStateChangeRequest>(hostDeviceKey, authMaintainState);
    if (!stateChangeRequest) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](stateChangeRequest, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
