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
#include "host_issue_token_request.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

constexpr int32_t INT32_100 = 100;

using HostIssueTokenRequestFuzzFunction = void (*)(std::shared_ptr<HostIssueTokenRequest> &request,
    FuzzedDataProvider &fuzzData);

static void FuzzGetMaxConcurrency(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetMaxConcurrency();
}

static void FuzzShouldCancelOnNewRequest(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    RequestType newRequestType = static_cast<RequestType>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, INT32_100));
    std::optional<DeviceKey> newPeerDevice;
    if (fuzzData.ConsumeBool()) {
        newPeerDevice = GenerateFuzzDeviceKey(fuzzData);
    }
    uint32_t subsequentSameTypeCount = fuzzData.ConsumeIntegral<uint32_t>();
    (void)request->ShouldCancelOnNewRequest(newRequestType, newPeerDevice, subsequentSameTypeCount);
}

static void FuzzOnStart(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ErrorGuard errorGuard([](ResultCode result) { (void)result; });
    (void)request->OnStart(errorGuard);
}

static void FuzzOnConnected(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->OnConnected();
}

static void FuzzCompleteWithError(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    request->CompleteWithError(result);
}

static void FuzzCompleteWithSuccess(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->CompleteWithSuccess();
}

static void FuzzGetWeakPtr(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetWeakPtr();
}

static void FuzzHostPreIssueToken(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->HostPreIssueToken();
}

static void FuzzSendPreIssueTokenRequest(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    uint32_t requestSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> preIssueTokenRequestData = fuzzData.ConsumeBytes<uint8_t>(requestSize);
    (void)request->SendPreIssueTokenRequest(preIssueTokenRequestData);
}

static void FuzzSendIssueTokenRequest(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    uint32_t requestSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> issueTokenRequestData = fuzzData.ConsumeBytes<uint8_t>(requestSize);
    (void)request->SendIssueTokenRequest(issueTokenRequestData);
}

static void FuzzHandlePreIssueTokenReply(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    Attributes message = GenerateFuzzAttributes(fuzzData);
    request->HandlePreIssueTokenReply(message);
}

static void FuzzHandleIssueTokenReply(std::shared_ptr<HostIssueTokenRequest> &request, FuzzedDataProvider &fuzzData)
{
    Attributes message = GenerateFuzzAttributes(fuzzData);
    request->HandleIssueTokenReply(message);
}

static void FuzzHandlePeerDeviceStatusChanged(std::shared_ptr<HostIssueTokenRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    uint8_t statusCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_DEVICE_STATUS_COUNT);
    std::vector<DeviceStatus> deviceStatusList = GenerateFuzzDeviceStatusList(fuzzData, statusCount);
    request->HandlePeerDeviceStatusChanged(deviceStatusList);
}

static const HostIssueTokenRequestFuzzFunction g_fuzzFuncs[] = {
    FuzzGetMaxConcurrency,
    FuzzShouldCancelOnNewRequest,
    FuzzOnStart,
    FuzzOnConnected,
    FuzzCompleteWithError,
    FuzzCompleteWithSuccess,
    FuzzGetWeakPtr,
    FuzzHostPreIssueToken,
    FuzzSendPreIssueTokenRequest,
    FuzzSendIssueTokenRequest,
    FuzzHandlePreIssueTokenReply,
    FuzzHandleIssueTokenReply,
    FuzzHandlePeerDeviceStatusChanged,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(HostIssueTokenRequestFuzzFunction);

void FuzzHostIssueTokenRequest(FuzzedDataProvider &fuzzData)
{
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    auto request = std::make_shared<HostIssueTokenRequest>(hostUserId, templateId, fwkMsg);
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

FUZZ_REGISTER(FuzzHostIssueTokenRequest)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
