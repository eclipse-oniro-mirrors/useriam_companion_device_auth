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
#include <optional>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "continuous_auth_subscription.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(std::shared_ptr<ContinuousAuthSubscription> &subscription, FuzzedDataProvider &fuzzData);

static void FuzzGetUserId(std::shared_ptr<ContinuousAuthSubscription> &subscription, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto userId = subscription->GetUserId();
    (void)userId;
}

static void FuzzGetTemplateId(std::shared_ptr<ContinuousAuthSubscription> &subscription, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto templateId = subscription->GetTemplateId();
    (void)templateId;
}

static void FuzzGetWeakPtr(std::shared_ptr<ContinuousAuthSubscription> &subscription, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto weakPtr = subscription->GetWeakPtr();
    (void)weakPtr;
}

static void FuzzOnCallbackAdded(std::shared_ptr<ContinuousAuthSubscription> &subscription, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    class FakeCallback : public IIpcContinuousAuthStatusCallback {
    public:
        ErrCode OnContinuousAuthStatusChange(const IpcContinuousAuthStatus &authStatus) override
        {
            (void)authStatus;
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

static void FuzzInitialize(std::shared_ptr<ContinuousAuthSubscription> &subscription, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    subscription->Initialize();
}

static void FuzzNotifyAuthStatus(std::shared_ptr<ContinuousAuthSubscription> &subscription,
    FuzzedDataProvider &fuzzData)
{
    std::optional<Atl> authTrustLevel;
    if (fuzzData.ConsumeBool()) {
        authTrustLevel = static_cast<Atl>(fuzzData.ConsumeIntegral<uint32_t>());
    }
    subscription->NotifyAuthStatus(authTrustLevel);
}

static void FuzzHandleCompanionStatusChange(std::shared_ptr<ContinuousAuthSubscription> &subscription,
    FuzzedDataProvider &fuzzData)
{
    std::vector<CompanionStatus> companionStatusList;
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    for (uint8_t i = 0; i < count; ++i) {
        CompanionStatus status;
        status.templateId = fuzzData.ConsumeIntegral<uint64_t>();
        status.hostUserId = fuzzData.ConsumeIntegral<int32_t>();
        status.addedTime = fuzzData.ConsumeIntegral<uint64_t>();
        status.companionDeviceStatus.secureProtocolId =
            static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
        status.isValid = fuzzData.ConsumeBool();
        companionStatusList.push_back(status);
    }
    subscription->HandleCompanionStatusChange(companionStatusList);
}

static void FuzzOnCallbackRemoteDied(std::shared_ptr<ContinuousAuthSubscription> &subscription,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    class FakeCallback : public IIpcContinuousAuthStatusCallback {
    public:
        ErrCode OnContinuousAuthStatusChange(const IpcContinuousAuthStatus &authStatus) override
        {
            (void)authStatus;
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

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzGetUserId,
    FuzzGetTemplateId,
    FuzzGetWeakPtr,
    FuzzOnCallbackAdded,
    FuzzInitialize,
    FuzzNotifyAuthStatus,
    FuzzHandleCompanionStatusChange,
    FuzzOnCallbackRemoteDied,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzContinuousAuthSubscription(FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    std::optional<TemplateId> templateId;
    if (fuzzData.ConsumeBool()) {
        templateId = fuzzData.ConsumeIntegral<TemplateId>();
    }

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, std::weak_ptr<SubscriptionManager>());
    if (!subscription) {
        return;
    }

    // Initialize the subscription
    subscription->Initialize();

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](subscription, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
