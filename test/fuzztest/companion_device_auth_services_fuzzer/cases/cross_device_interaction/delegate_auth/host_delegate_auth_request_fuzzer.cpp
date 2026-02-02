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
#include "host_delegate_auth_request.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using HostDelegateAuthRequestFuzzFunction = void (*)(std::shared_ptr<HostDelegateAuthRequest> &request,
    FuzzedDataProvider &fuzzData);

static void FuzzGetMaxConcurrency(std::shared_ptr<HostDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetMaxConcurrency();
}

static void FuzzShouldCancelOnNewRequest(std::shared_ptr<HostDelegateAuthRequest> &request,
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

static void FuzzOnStart(std::shared_ptr<HostDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ErrorGuard errorGuard([](ResultCode result) { (void)result; });
    (void)request->OnStart(errorGuard);
}

static void FuzzOnConnected(std::shared_ptr<HostDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->OnConnected();
}

static void FuzzCompleteWithError(std::shared_ptr<HostDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    request->CompleteWithError(result);
}

static void FuzzGetWeakPtr(std::shared_ptr<HostDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetWeakPtr();
}

static void FuzzGetRequestInfo(std::shared_ptr<HostDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetRequestType();
    (void)request->GetScheduleId();
}

static void FuzzGetPeerInfo(std::shared_ptr<HostDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetPeerDeviceKey();
    (void)request->GetDescription();
}

static void FuzzHostBeginDelegateAuth(std::shared_ptr<HostDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->HostBeginDelegateAuth();
}

static void FuzzGetDescription(std::shared_ptr<HostDelegateAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetDescription();
}

static void FuzzHandleStartDelegateAuthReply(std::shared_ptr<HostDelegateAuthRequest> &request,
    FuzzedDataProvider &fuzzData)
{
    Attributes replyMsg = GenerateFuzzAttributes(fuzzData);
    request->HandleStartDelegateAuthReply(replyMsg);
}

static const HostDelegateAuthRequestFuzzFunction g_fuzzFuncs[] = {
    FuzzGetMaxConcurrency,
    FuzzShouldCancelOnNewRequest,
    FuzzOnStart,
    FuzzOnConnected,
    FuzzCompleteWithError,
    FuzzGetWeakPtr,
    FuzzGetRequestInfo,
    FuzzGetPeerInfo,
    FuzzHostBeginDelegateAuth,
    FuzzGetDescription,
    FuzzHandleStartDelegateAuthReply,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(HostDelegateAuthRequestFuzzFunction);

void FuzzHostDelegateAuthRequest(FuzzedDataProvider &fuzzData)
{
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();

    FwkResultCallback callback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };

    auto request =
        std::make_shared<HostDelegateAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId, std::move(callback));
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

FUZZ_REGISTER(FuzzHostDelegateAuthRequest)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
