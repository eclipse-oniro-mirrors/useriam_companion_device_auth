/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "service_common.h"
#include "sub_profile_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr int32_t INT32_100 = 100;
} // namespace

using SubProfileIdManagerFuzzFunction = void (*)(ISubProfileIdManager &manager, FuzzedDataProvider &fuzzData);

static void FuzzGetForegroundSubProfileId(ISubProfileIdManager &manager, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    auto result = manager.GetForegroundSubProfileId(userId);
    (void)result;
}

static void FuzzGetSubProfileName(ISubProfileIdManager &manager, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    int32_t subProfileId = fuzzData.ConsumeIntegral<int32_t>();
    auto result = manager.GetSubProfileName(userId, subProfileId);
    (void)result;
}

static void FuzzIsForegroundSubProfileId(ISubProfileIdManager &manager, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    int32_t subProfileId = fuzzData.ConsumeIntegral<int32_t>();
    auto result = manager.IsForegroundSubProfileId(userId, subProfileId);
    (void)result;
}

static void FuzzSubscribeSubProfileChanged(ISubProfileIdManager &manager, FuzzedDataProvider &fuzzData)
{
    bool useNullCallback = fuzzData.ConsumeBool();
    if (useNullCallback) {
        auto sub = manager.SubscribeSubProfileChanged(nullptr);
        (void)sub;
    } else {
        auto sub = manager.SubscribeSubProfileChanged(
            [](UserId userId, int32_t subProfileId, SubProfileEventType eventType) {
                (void)userId;
                (void)subProfileId;
                (void)eventType;
            });
        (void)sub;
    }
}

static void FuzzGetForegroundSubProfileIdBoundary(ISubProfileIdManager &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::vector<UserId> testUserIds = { 0, INT32_100, INVALID_USER_ID, INT32_MAX, INT32_MIN };
    for (auto userId : testUserIds) {
        auto result = manager.GetForegroundSubProfileId(userId);
        (void)result;
    }
}

static void FuzzGetSubProfileNameBoundary(ISubProfileIdManager &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::vector<int32_t> testSubProfileIds = { 0, INT32_100, INVALID_SUB_PROFILE_ID, INT32_MAX, INT32_MIN };
    for (auto subProfileId : testSubProfileIds) {
        auto result = manager.GetSubProfileName(INT32_100, subProfileId);
        (void)result;
    }
}

static void FuzzIsForegroundSubProfileIdBoundary(ISubProfileIdManager &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::vector<int32_t> testSubProfileIds = { 0, INT32_100, INVALID_SUB_PROFILE_ID, INT32_MAX, INT32_MIN };
    for (auto subProfileId : testSubProfileIds) {
        auto result = manager.IsForegroundSubProfileId(INT32_100, subProfileId);
        (void)result;
    }
}

static const SubProfileIdManagerFuzzFunction FUZZ_FUNCS[] = {
    FuzzGetForegroundSubProfileId,
    FuzzGetSubProfileName,
    FuzzIsForegroundSubProfileId,
    FuzzSubscribeSubProfileChanged,
    FuzzGetForegroundSubProfileIdBoundary,
    FuzzGetSubProfileNameBoundary,
    FuzzIsForegroundSubProfileIdBoundary,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(FUZZ_FUNCS) / sizeof(SubProfileIdManagerFuzzFunction);

void FuzzSubProfileIdManager(FuzzedDataProvider &fuzzData)
{
    auto manager = ISubProfileIdManager::Create();
    if (manager == nullptr) {
        return;
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        FUZZ_FUNCS[operation](*manager, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzSubProfileIdManager)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
