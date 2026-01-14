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
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using ChannelManagerFuzzFunction = void (*)(std::shared_ptr<ChannelManager> &mgr, FuzzedDataProvider &fuzzData);

static void FuzzGetPrimaryChannel(std::shared_ptr<ChannelManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (mgr) {
        auto channel = mgr->GetPrimaryChannel();
        (void)channel;
    }
}

static void FuzzGetChannelById(std::shared_ptr<ChannelManager> &mgr, FuzzedDataProvider &fuzzData)
{
    int32_t channelIdValue = fuzzData.ConsumeIntegral<int32_t>();
    ChannelId channelId = static_cast<ChannelId>(channelIdValue);
    if (mgr) {
        auto channel = mgr->GetChannelById(channelId);
        (void)channel;
    }
}

static void FuzzGetAllChannels(std::shared_ptr<ChannelManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (mgr) {
        auto channels = mgr->GetAllChannels();
        (void)channels;
    }
}

// Test GetChannelById with various channel IDs including boundary values
static void FuzzGetChannelByIdBoundary(std::shared_ptr<ChannelManager> &mgr, FuzzedDataProvider &fuzzData)
{
    if (mgr) {
        // Test with different boundary channel IDs
        std::vector<ChannelId> testIds = {
            static_cast<ChannelId>(0),   // Min value
            static_cast<ChannelId>(-1),  // Max value
            static_cast<ChannelId>(999), // Invalid mid-range
        };
        for (auto channelId : testIds) {
            auto channel = mgr->GetChannelById(channelId);
            (void)channel;
        }
        // Also test with fuzzed channel ID
        int32_t fuzzedIdValue = fuzzData.ConsumeIntegral<int32_t>();
        ChannelId fuzzedId = static_cast<ChannelId>(fuzzedIdValue);
        auto channel = mgr->GetChannelById(fuzzedId);
        (void)channel;
    }
}

// Test repeated GetPrimaryChannel calls
static void FuzzRepeatedGetPrimary(std::shared_ptr<ChannelManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    int num = 10;
    if (mgr) {
        for (int i = 0; i < num; ++i) {
            auto channel = mgr->GetPrimaryChannel();
            (void)channel;
        }
    }
}

// Test GetAllChannels multiple times
static void FuzzGetAllChannelsRepeated(std::shared_ptr<ChannelManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    int num = 5;
    if (mgr) {
        for (int i = 0; i < num; ++i) {
            auto channels = mgr->GetAllChannels();
            (void)channels;
        }
    }
}

// Test GetChannelById with fuzzed channel ID
static void FuzzGetChannelByRandomId(std::shared_ptr<ChannelManager> &mgr, FuzzedDataProvider &fuzzData)
{
    int32_t channelIdValue = fuzzData.ConsumeIntegral<int32_t>();
    ChannelId channelId = static_cast<ChannelId>(channelIdValue);
    int num = 3;
    if (mgr) {
        for (int i = 0; i < num; ++i) {
            auto channel = mgr->GetChannelById(channelId);
            (void)channel;
        }
    }
}

// Test combination: GetPrimaryChannel then GetAllChannels
static void FuzzGetPrimaryThenAll(std::shared_ptr<ChannelManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (mgr) {
        auto primary = mgr->GetPrimaryChannel();
        auto all = mgr->GetAllChannels();
        (void)primary;
        (void)all;
    }
}

// Test GetChannelById with same ID multiple times
static void FuzzSameChannelId(std::shared_ptr<ChannelManager> &mgr, FuzzedDataProvider &fuzzData)
{
    ChannelId channelId = GenerateFuzzChannelId(fuzzData);
    int num = 7;
    if (mgr) {
        for (int i = 0; i < num; ++i) {
            auto channel = mgr->GetChannelById(channelId);
            (void)channel;
        }
    }
}

// Test sequential access to all channels
static void FuzzSequentialChannelAccess(std::shared_ptr<ChannelManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (mgr) {
        auto allChannels = mgr->GetAllChannels();
        auto primary = mgr->GetPrimaryChannel();
        (void)allChannels;
        (void)primary;

        if (!allChannels.empty()) {
            auto firstChannel = allChannels[0];
            (void)firstChannel;
        }
    }
}

static const ChannelManagerFuzzFunction g_fuzzFuncs[] = {
    FuzzGetPrimaryChannel,
    FuzzGetChannelById,
    FuzzGetAllChannels,
    FuzzGetChannelByIdBoundary,
    FuzzRepeatedGetPrimary,
    FuzzGetAllChannelsRepeated,
    FuzzGetChannelByRandomId,
    FuzzGetPrimaryThenAll,
    FuzzSameChannelId,
    FuzzSequentialChannelAccess,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(ChannelManagerFuzzFunction);

void FuzzChannelManager(FuzzedDataProvider &fuzzData)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    auto mgr = std::make_shared<ChannelManager>(channels);
    if (!mgr) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);

    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](mgr, fuzzData);
    }

    EnsureAllTaskExecuted();
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(ChannelManager)

} // namespace UserIam
} // namespace OHOS
