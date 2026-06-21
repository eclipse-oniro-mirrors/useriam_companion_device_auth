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

#include "base_service_core.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "subscription_manager.h"
#include "task_runner_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SubscriptionManager;

using BaseServiceCoreFuzzFunction = void (*)(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &);

static void FuzzSubscribeAvailableDeviceStatus(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &fuzzData)
{
    int32_t localUserId = fuzzData.ConsumeIntegral<int32_t>();
    sptr<IIpcAvailableDeviceStatusCallback> callback = nullptr;
    (void)core->SubscribeAvailableDeviceStatus(localUserId, callback);
}

static void FuzzUnsubscribeAvailableDeviceStatus(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &fuzzData)
{
    sptr<IIpcAvailableDeviceStatusCallback> callback = nullptr;
    (void)core->UnsubscribeAvailableDeviceStatus(callback);
}

static void FuzzSubscribeTemplateStatusChange(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &fuzzData)
{
    int32_t localUserId = fuzzData.ConsumeIntegral<int32_t>();
    sptr<IIpcTemplateStatusCallback> callback = nullptr;
    (void)core->SubscribeTemplateStatusChange(localUserId, callback);
}

static void FuzzUnsubscribeTemplateStatusChange(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &fuzzData)
{
    sptr<IIpcTemplateStatusCallback> callback = nullptr;
    (void)core->UnsubscribeTemplateStatusChange(callback);
}

static void FuzzSubscribeContinuousAuthStatusChange(std::shared_ptr<BaseServiceCore> &core,
    FuzzedDataProvider &fuzzData)
{
    IpcSubscribeContinuousAuthStatusParam param;
    param.localUserId = fuzzData.ConsumeIntegral<int32_t>();
    param.hasTemplateId = fuzzData.ConsumeBool();
    if (param.hasTemplateId) {
        param.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    }

    sptr<IIpcContinuousAuthStatusCallback> callback = nullptr;
    (void)core->SubscribeContinuousAuthStatusChange(param, callback);
}

static void FuzzUnsubscribeContinuousAuthStatusChange(std::shared_ptr<BaseServiceCore> &core,
    FuzzedDataProvider &fuzzData)
{
    sptr<IIpcContinuousAuthStatusCallback> callback = nullptr;
    (void)core->UnsubscribeContinuousAuthStatusChange(callback);
}

static void FuzzUpdateTemplateEnabledBusinessIds(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &fuzzData)
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

    (void)core->UpdateTemplateEnabledBusinessIds(templateId, businessIds);
}

static void FuzzGetTemplateStatus(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &fuzzData)
{
    int32_t localUserId = fuzzData.ConsumeIntegral<int32_t>();
    std::vector<IpcTemplateStatus> templateStatusArray;
    (void)core->GetTemplateStatus(localUserId, templateStatusArray);
}

static void FuzzRegisterDeviceSelectCallback(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    sptr<IIpcDeviceSelectCallback> callback = nullptr;
    (void)core->RegisterDeviceSelectCallback(tokenId, callback);
}

static void FuzzUnregisterDeviceSelectCallback(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    (void)core->UnregisterDeviceSelectCallback(tokenId);
}

static void FuzzCheckLocalUserIdValid(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &fuzzData)
{
    int32_t localUserId = fuzzData.ConsumeIntegral<int32_t>();
    (void)core->CheckLocalUserIdValid(localUserId);
}

// CallbackEnter and CallbackExit are CompanionDeviceAuthService-specific logging methods
// not available on BaseServiceCore. These are no-ops for fuzz testing since they only log.
static void FuzzCallbackEnter(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &fuzzData)
{
    (void)core;
    (void)fuzzData.ConsumeIntegral<uint32_t>();
}

static void FuzzCallbackExit(std::shared_ptr<BaseServiceCore> &core, FuzzedDataProvider &fuzzData)
{
    (void)core;
    (void)fuzzData.ConsumeIntegral<uint32_t>();
    (void)fuzzData.ConsumeIntegral<int32_t>();
}

static const BaseServiceCoreFuzzFunction g_fuzzFuncs[] = {
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

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(BaseServiceCoreFuzzFunction);

void FuzzCompanionDeviceAuthService(FuzzedDataProvider &fuzzData)
{
    static const std::vector<BusinessId> supportedBusinessIds = { BusinessId::DEFAULT };
    static std::shared_ptr<BaseServiceCore> core =
        BaseServiceCore::Create(std::make_shared<SubscriptionManager>(), supportedBusinessIds, supportedBusinessIds);
    if (core == nullptr) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](core, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](core, fuzzData);
    }

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzCompanionDeviceAuthService)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
