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

#include "companion_device_auth_service.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using CompanionDeviceAuthServiceFuzzFunction = void (*)(sptr<CompanionDeviceAuthService> &service,
    FuzzedDataProvider &);

static void FuzzSubscribeAvailableDeviceStatus(sptr<CompanionDeviceAuthService> &service, FuzzedDataProvider &fuzzData)
{
    int32_t localUserId = fuzzData.ConsumeIntegral<int32_t>();
    sptr<IIpcAvailableDeviceStatusCallback> callback = nullptr;
    int32_t result = 0;
    service->SubscribeAvailableDeviceStatus(localUserId, callback, result);
    (void)result;
}

static void FuzzUnsubscribeAvailableDeviceStatus(sptr<CompanionDeviceAuthService> &service,
    FuzzedDataProvider &fuzzData)
{
    sptr<IIpcAvailableDeviceStatusCallback> callback = nullptr;
    int32_t result = 0;
    service->UnsubscribeAvailableDeviceStatus(callback, result);
    (void)result;
}

static void FuzzSubscribeTemplateStatusChange(sptr<CompanionDeviceAuthService> &service, FuzzedDataProvider &fuzzData)
{
    int32_t localUserId = fuzzData.ConsumeIntegral<int32_t>();
    sptr<IIpcTemplateStatusCallback> callback = nullptr;
    int32_t result = 0;
    service->SubscribeTemplateStatusChange(localUserId, callback, result);
    (void)result;
}

static void FuzzUnsubscribeTemplateStatusChange(sptr<CompanionDeviceAuthService> &service, FuzzedDataProvider &fuzzData)
{
    sptr<IIpcTemplateStatusCallback> callback = nullptr;
    int32_t result = 0;
    service->UnsubscribeTemplateStatusChange(callback, result);
    (void)result;
}

static void FuzzSubscribeContinuousAuthStatusChange(sptr<CompanionDeviceAuthService> &service,
    FuzzedDataProvider &fuzzData)
{
    IpcSubscribeContinuousAuthStatusParam param;
    param.localUserId = fuzzData.ConsumeIntegral<int32_t>();
    param.hasTemplateId = fuzzData.ConsumeBool();
    if (param.hasTemplateId) {
        param.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    }

    sptr<IIpcContinuousAuthStatusCallback> callback = nullptr;
    int32_t result = 0;
    service->SubscribeContinuousAuthStatusChange(param, callback, result);
    (void)result;
}

static void FuzzUnsubscribeContinuousAuthStatusChange(sptr<CompanionDeviceAuthService> &service,
    FuzzedDataProvider &fuzzData)
{
    sptr<IIpcContinuousAuthStatusCallback> callback = nullptr;
    int32_t result = 0;
    service->UnsubscribeContinuousAuthStatusChange(callback, result);
    (void)result;
}

static void FuzzUpdateTemplateEnabledBusinessIds(sptr<CompanionDeviceAuthService> &service,
    FuzzedDataProvider &fuzzData)
{
    uint64_t templateId = fuzzData.ConsumeIntegral<uint64_t>();

    // Generate BusinessId vector and convert to int32_t for the API
    std::vector<BusinessId> businessIdEnums;
    GenerateFuzzBusinessIds(fuzzData, businessIdEnums, FUZZ_MAX_BUSINESS_IDS_COUNT);

    std::vector<int32_t> businessIds;
    businessIds.reserve(businessIdEnums.size());
    for (const auto &id : businessIdEnums) {
        businessIds.push_back(static_cast<int32_t>(id));
    }

    int32_t result = 0;
    service->UpdateTemplateEnabledBusinessIds(templateId, businessIds, result);
    (void)result;
}

static void FuzzGetTemplateStatus(sptr<CompanionDeviceAuthService> &service, FuzzedDataProvider &fuzzData)
{
    int32_t localUserId = fuzzData.ConsumeIntegral<int32_t>();
    std::vector<IpcTemplateStatus> templateStatusArray;
    int32_t result = 0;
    service->GetTemplateStatus(localUserId, templateStatusArray, result);
    (void)result;
}

static void FuzzRegisterDeviceSelectCallback(sptr<CompanionDeviceAuthService> &service, FuzzedDataProvider &fuzzData)
{
    sptr<IIpcDeviceSelectCallback> callback = nullptr;
    int32_t result = 0;
    service->RegisterDeviceSelectCallback(callback, result);
    (void)result;
}

static void FuzzUnregisterDeviceSelectCallback(sptr<CompanionDeviceAuthService> &service, FuzzedDataProvider &fuzzData)
{
    int32_t result = 0;
    service->UnregisterDeviceSelectCallback(result);
    (void)result;
}

static void FuzzCheckLocalUserIdValid(sptr<CompanionDeviceAuthService> &service, FuzzedDataProvider &fuzzData)
{
    int32_t localUserId = fuzzData.ConsumeIntegral<int32_t>();
    bool isUserIdValid = false;
    int32_t result = 0;
    service->CheckLocalUserIdValid(localUserId, isUserIdValid, result);
    (void)isUserIdValid;
    (void)result;
}

static void FuzzCallbackEnter(sptr<CompanionDeviceAuthService> &service, FuzzedDataProvider &fuzzData)
{
    uint32_t code = fuzzData.ConsumeIntegral<uint32_t>();
    service->CallbackEnter(code);
}

static void FuzzCallbackExit(sptr<CompanionDeviceAuthService> &service, FuzzedDataProvider &fuzzData)
{
    uint32_t code = fuzzData.ConsumeIntegral<uint32_t>();
    int32_t result = fuzzData.ConsumeIntegral<int32_t>();
    service->CallbackExit(code, result);
}

static const CompanionDeviceAuthServiceFuzzFunction g_fuzzFuncs[] = {
    FuzzSubscribeAvailableDeviceStatus,
    FuzzUnsubscribeAvailableDeviceStatus,
    FuzzSubscribeTemplateStatusChange,
    FuzzUnsubscribeTemplateStatusChange,
    FuzzSubscribeContinuousAuthStatusChange,
    FuzzUnsubscribeContinuousAuthStatusChange,
    FuzzUpdateTemplateEnabledBusinessIds,
    FuzzGetTemplateStatus,
    FuzzRegisterDeviceSelectCallback,
    FuzzUnregisterDeviceSelectCallback,
    FuzzCheckLocalUserIdValid,
    FuzzCallbackEnter,
    FuzzCallbackExit,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(CompanionDeviceAuthServiceFuzzFunction);

void FuzzCompanionDeviceAuthService(FuzzedDataProvider &fuzzData)
{
    auto service = CompanionDeviceAuthService::GetInstance();
    if (service == nullptr) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);

    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](service, fuzzData);
    }

    EnsureAllTaskExecuted();
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(CompanionDeviceAuthService)

} // namespace UserIam
} // namespace OHOS
