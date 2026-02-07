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

#include "channel_manager.h"
#include "fuzz_constants.h"
#include "fuzz_cross_device_channel.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "local_device_status_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using LocalDeviceStatusManagerFuzzFunction = void (*)(std::shared_ptr<LocalDeviceStatusManager> &mgr,
    FuzzedDataProvider &fuzzData);

static void FuzzGetLocalDeviceProfile(std::shared_ptr<LocalDeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto profile = mgr->GetLocalDeviceProfile();
    (void)profile;
}

static void FuzzGetLocalDeviceKey(std::shared_ptr<LocalDeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    ChannelId channelId = GenerateFuzzChannelId(fuzzData);
    auto key = mgr->GetLocalDeviceKey(channelId);
    (void)key;
}

static void FuzzGetLocalDeviceKeys(std::shared_ptr<LocalDeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto keys = mgr->GetLocalDeviceKeys();
    (void)keys;
}

static void FuzzIsAuthMaintainActive(std::shared_ptr<LocalDeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    bool isActive = mgr->IsAuthMaintainActive();
    (void)isActive;
}

static void FuzzSetAuthMaintainActive(std::shared_ptr<LocalDeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    bool isActive = fuzzData.ConsumeBool();
    mgr->SetAuthMaintainActive(isActive);
}

static void FuzzSubscribeIsAuthMaintainActive(std::shared_ptr<LocalDeviceStatusManager> &mgr,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto subscription = mgr->SubscribeIsAuthMaintainActive([](bool active) { (void)active; });
    (void)subscription;
}

// Note: These functions access private members, enabled by -Dprivate=public in fuzzer build
static void FuzzInitialize(std::shared_ptr<LocalDeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    mgr->Initialize();
}

static void FuzzNotifyStatusChange(std::shared_ptr<LocalDeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    mgr->NotifyStatusChange();
}

static void FuzzUnsubscribe(std::shared_ptr<LocalDeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    int32_t subscriptionId = fuzzData.ConsumeIntegral<int32_t>();
    mgr->Unsubscribe(subscriptionId);
}

static void FuzzOnActiveUserIdChanged(std::shared_ptr<LocalDeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    mgr->OnActiveUserIdChanged(userId);
}

static const LocalDeviceStatusManagerFuzzFunction g_fuzzFuncs[] = {
    FuzzGetLocalDeviceProfile,
    FuzzGetLocalDeviceKey,
    FuzzGetLocalDeviceKeys,
    FuzzIsAuthMaintainActive,
    FuzzSetAuthMaintainActive,
    FuzzSubscribeIsAuthMaintainActive,
    FuzzInitialize,
    FuzzNotifyStatusChange,
    FuzzUnsubscribe,
    FuzzOnActiveUserIdChanged,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(LocalDeviceStatusManagerFuzzFunction);

void FuzzLocalDeviceStatusManager(FuzzedDataProvider &fuzzData)
{
    auto fuzzChannel = std::make_shared<FuzzCrossDeviceChannel>(fuzzData);
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    channels.push_back(fuzzChannel);

    auto channelMgr = std::make_shared<ChannelManager>(channels);
    if (!channelMgr) {
        return;
    }

    auto mgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    if (!mgr) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](mgr, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](mgr, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzLocalDeviceStatusManager)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
