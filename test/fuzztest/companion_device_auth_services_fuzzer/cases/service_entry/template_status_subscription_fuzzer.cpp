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
#include "subscription_manager.h"
#include "template_status_subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr uint32_t SIZE_64 = 64;
constexpr int32_t INT32_3 = 3;
} // namespace

using TemplateStatusSubscriptionFuzzFunction = void (*)(std::shared_ptr<TemplateStatusSubscription> &subscription,
    FuzzedDataProvider &fuzzData);

static void FuzzGetUserId(std::shared_ptr<TemplateStatusSubscription> &subscription, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto userId = subscription->GetUserId();
    (void)userId;
}

static void FuzzGetWeakPtr(std::shared_ptr<TemplateStatusSubscription> &subscription, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto weakPtr = subscription->GetWeakPtr();
    (void)weakPtr;
}

static void FuzzHandleCompanionStatusChange(std::shared_ptr<TemplateStatusSubscription> &subscription,
    FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_CAPABILITIES_COUNT);
    std::vector<CompanionStatus> companionStatusList;
    uint32_t testVal64 = SIZE_64;
    uint8_t leftRange = 0;
    uint8_t rightRange = INT32_3;
    for (uint8_t i = 0; i < count; ++i) {
        CompanionStatus status;
        status.templateId = fuzzData.ConsumeIntegral<TemplateId>();
        status.hostUserId = fuzzData.ConsumeIntegral<UserId>();
        status.companionDeviceStatus.deviceKey.idType =
            static_cast<DeviceIdType>(fuzzData.ConsumeIntegralInRange<uint8_t>(leftRange, rightRange));
        status.companionDeviceStatus.deviceKey.deviceId = GenerateFuzzString(fuzzData, testVal64);
        status.companionDeviceStatus.deviceKey.deviceUserId = fuzzData.ConsumeIntegral<UserId>();
        status.companionDeviceStatus.deviceName = GenerateFuzzString(fuzzData, testVal64);
        status.companionDeviceStatus.isOnline = fuzzData.ConsumeBool();
        status.isValid = fuzzData.ConsumeBool();
        companionStatusList.push_back(status);
    }
    subscription->HandleCompanionStatusChange(companionStatusList);
}

static void FuzzOnCallbackAdded(std::shared_ptr<TemplateStatusSubscription> &subscription, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    class FakeCallback : public IIpcTemplateStatusCallback {
    public:
        ErrCode OnTemplateStatusChange(const std::vector<IpcTemplateStatus> &templateStatusList) override
        {
            (void)templateStatusList;
            return SUCCESS;
        }
        sptr<IRemoteObject> AsObject() override
        {
            return nullptr;
        }
    };
    sptr<FakeCallback> callback = new FakeCallback();
    subscription->OnCallbackAdded(callback);
}

static void FuzzOnCallbackRemoteDied(std::shared_ptr<TemplateStatusSubscription> &subscription,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    class FakeCallback : public IIpcTemplateStatusCallback {
    public:
        ErrCode OnTemplateStatusChange(const std::vector<IpcTemplateStatus> &templateStatusList) override
        {
            (void)templateStatusList;
            return SUCCESS;
        }
        sptr<IRemoteObject> AsObject() override
        {
            return nullptr;
        }
    };
    sptr<FakeCallback> callback = new FakeCallback();
    subscription->OnCallbackRemoteDied(callback);
}

static const TemplateStatusSubscriptionFuzzFunction g_fuzzFuncs[] = {
    FuzzGetUserId,
    FuzzGetWeakPtr,
    FuzzHandleCompanionStatusChange,
    FuzzOnCallbackAdded,
    FuzzOnCallbackRemoteDied,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(TemplateStatusSubscriptionFuzzFunction);

void FuzzTemplateStatusSubscription(FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    auto subscription = TemplateStatusSubscription::Create(userId, std::weak_ptr<SubscriptionManager>());
    if (!subscription) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](subscription, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](subscription, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzTemplateStatusSubscription)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
