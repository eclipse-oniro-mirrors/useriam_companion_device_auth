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

#include "available_device_subscription.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(std::shared_ptr<AvailableDeviceSubscription> &subscription, FuzzedDataProvider &fuzzData);

static void FuzzGetUserId(std::shared_ptr<AvailableDeviceSubscription> &subscription, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto userId = subscription->GetUserId();
    (void)userId;
}

static void FuzzGetWeakPtr(std::shared_ptr<AvailableDeviceSubscription> &subscription, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto weakPtr = subscription->GetWeakPtr();
    (void)weakPtr;
}

static void FuzzOnCallbackAdded(std::shared_ptr<AvailableDeviceSubscription> &subscription,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    class FakeCallback : public IIpcAvailableDeviceStatusCallback {
    public:
        ErrCode OnAvailableDeviceStatusChange(const std::vector<IpcDeviceStatus> &deviceStatusList) override
        {
            (void)deviceStatusList;
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

static void FuzzOnCallbackRemoteDied(std::shared_ptr<AvailableDeviceSubscription> &subscription,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    class FakeCallback : public IIpcAvailableDeviceStatusCallback {
    public:
        ErrCode OnAvailableDeviceStatusChange(const std::vector<IpcDeviceStatus> &deviceStatusList) override
        {
            (void)deviceStatusList;
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
    FuzzGetWeakPtr,
    FuzzOnCallbackAdded,
    FuzzOnCallbackRemoteDied,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzAvailableDeviceSubscription(FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    std::weak_ptr<SubscriptionManager> subscriptionManager;
    auto subscription = AvailableDeviceSubscription::Create(userId, subscriptionManager);
    if (!subscription) {
        return;
    }

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
