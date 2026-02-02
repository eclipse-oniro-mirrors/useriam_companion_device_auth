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
#include "host_sync_device_status_request.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using HostSyncDeviceStatusRequestFuzzFunction = void (*)(std::shared_ptr<HostSyncDeviceStatusRequest> &,
    FuzzedDataProvider &);

constexpr int32_t INT32_20 = 20;

static void FuzzOp0(std::shared_ptr<HostSyncDeviceStatusRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetMaxConcurrency
    (void)request->GetMaxConcurrency();
}

static void FuzzOp1(std::shared_ptr<HostSyncDeviceStatusRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test ShouldCancelOnNewRequest
    RequestType newRequestType = static_cast<RequestType>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, INT32_20));
    std::optional<DeviceKey> newPeerDevice;
    if (fuzzData.ConsumeBool()) {
        newPeerDevice = GenerateFuzzDeviceKey(fuzzData);
    }
    uint32_t subsequentSameTypeCount = fuzzData.ConsumeIntegral<uint32_t>();
    (void)request->ShouldCancelOnNewRequest(newRequestType, newPeerDevice, subsequentSameTypeCount);
}

static void FuzzOp2(std::shared_ptr<HostSyncDeviceStatusRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test OnConnected
    request->OnConnected();
}

static void FuzzOp3(std::shared_ptr<HostSyncDeviceStatusRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetWeakPtr
    (void)request->GetWeakPtr();
}

static void FuzzOp4(std::shared_ptr<HostSyncDeviceStatusRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test CompleteWithError
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    request->CompleteWithError(result);
}

static void FuzzOp5(std::shared_ptr<HostSyncDeviceStatusRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test BeginCompanionCheck (protected method)
    request->BeginCompanionCheck();
}

static void FuzzOp6(std::shared_ptr<HostSyncDeviceStatusRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SendSyncDeviceStatusRequest (protected method)
    uint32_t saltSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_SALT_LENGTH);
    std::vector<uint8_t> salt = fuzzData.ConsumeBytes<uint8_t>(saltSize);
    uint64_t challenge = fuzzData.ConsumeIntegral<uint64_t>();
    (void)request->SendSyncDeviceStatusRequest(salt, challenge);
}

static void FuzzOp7(std::shared_ptr<HostSyncDeviceStatusRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test HandleSyncDeviceStatusReply (protected method)
    Attributes reply = GenerateFuzzAttributes(fuzzData);
    request->HandleSyncDeviceStatusReply(reply);
}

static void FuzzOp8(std::shared_ptr<HostSyncDeviceStatusRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test NeedBeginCompanionCheck (protected method)
    (void)request->NeedBeginCompanionCheck();
}

static void FuzzOp9(std::shared_ptr<HostSyncDeviceStatusRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test Cancel (base method)
    ResultCode resultCode = GenerateFuzzResultCode(fuzzData);
    (void)request->Cancel(resultCode);
}

static const HostSyncDeviceStatusRequestFuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3, FuzzOp4,
    FuzzOp5, FuzzOp6, FuzzOp7, FuzzOp8, FuzzOp9 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(HostSyncDeviceStatusRequestFuzzFunction);

void FuzzHostSyncDeviceStatusRequest(FuzzedDataProvider &fuzzData)
{
    int32_t hostUserId = fuzzData.ConsumeIntegral<int32_t>();
    DeviceKey companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    std::string companionDeviceName = GenerateFuzzString(fuzzData, TEST_VAL64);
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};

    auto request = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId, companionDeviceKey, companionDeviceName,
        std::move(callback));
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
    }

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzHostSyncDeviceStatusRequest)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
