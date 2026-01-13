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
#include "host_token_auth_request.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using HostTokenAuthRequestFuzzFunction = void (*)(std::shared_ptr<HostTokenAuthRequest> &request,
    FuzzedDataProvider &fuzzData);

static void FuzzGetMaxConcurrency(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetMaxConcurrency();
}

static void FuzzShouldCancelOnNewRequest(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    RequestType newRequestType = static_cast<RequestType>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, 20));
    std::optional<DeviceKey> newPeerDevice;
    if (fuzzData.ConsumeBool()) {
        newPeerDevice = GenerateFuzzDeviceKey(fuzzData);
    }
    uint32_t subsequentSameTypeCount = fuzzData.ConsumeIntegral<uint32_t>();
    (void)request->ShouldCancelOnNewRequest(newRequestType, newPeerDevice, subsequentSameTypeCount);
}

static void FuzzOnStart(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ErrorGuard errorGuard([](ResultCode result) { (void)result; });
    (void)request->OnStart(errorGuard);
}

static void FuzzOnConnected(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->OnConnected();
}

static void FuzzCompleteWithError(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    request->CompleteWithError(result);
}

static void FuzzCompleteWithSuccess(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    std::vector<uint8_t> extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    request->CompleteWithSuccess(extraInfo);
}

static void FuzzGetWeakPtr(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetWeakPtr();
}

static void FuzzSendTokenAuthRequest(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    uint32_t tokenAuthRequestSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> tokenAuthRequest = fuzzData.ConsumeBytes<uint8_t>(tokenAuthRequestSize);
    (void)request->SendTokenAuthRequest(tokenAuthRequest);
}

static void FuzzHandleTokenAuthReply(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    Attributes reply = GenerateFuzzAttributes(fuzzData);
    request->HandleTokenAuthReply(reply);
}

static void FuzzHostBeginTokenAuth(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    request->HostBeginTokenAuth();
}

static void FuzzSecureAgentEndTokenAuth(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    uint32_t tokenAuthReplySize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> tokenAuthReply = fuzzData.ConsumeBytes<uint8_t>(tokenAuthReplySize);
    std::vector<uint8_t> outFwkMsg;
    (void)request->SecureAgentEndTokenAuth(tokenAuthReply, outFwkMsg);
}

static void FuzzGetRequestInfo(std::shared_ptr<HostTokenAuthRequest> &request, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)request->GetRequestType();
    (void)request->GetScheduleId();
    (void)request->GetPeerDeviceKey();
}

static const HostTokenAuthRequestFuzzFunction g_fuzzFuncs[] = {
    FuzzGetMaxConcurrency,
    FuzzShouldCancelOnNewRequest,
    FuzzOnStart,
    FuzzOnConnected,
    FuzzCompleteWithError,
    FuzzCompleteWithSuccess,
    FuzzGetWeakPtr,
    FuzzSendTokenAuthRequest,
    FuzzHandleTokenAuthReply,
    FuzzHostBeginTokenAuth,
    FuzzSecureAgentEndTokenAuth,
    FuzzGetRequestInfo,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(HostTokenAuthRequestFuzzFunction);

void FuzzHostTokenAuthRequest(FuzzedDataProvider &fuzzData)
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
        std::make_shared<HostTokenAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId, std::move(callback));
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

FUZZ_REGISTER(HostTokenAuthRequest)

} // namespace UserIam
} // namespace OHOS
