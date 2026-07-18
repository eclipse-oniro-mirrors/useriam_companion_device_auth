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
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "interaction_event_collector.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using CollectorFuzzFunction = void (*)(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData);

static void FuzzSetHostUserId(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetHostUserId(fuzzData.ConsumeIntegral<UserId>());
}

static void FuzzSetCompanionUserId(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetCompanionUserId(fuzzData.ConsumeIntegral<UserId>());
}

static void FuzzSetConnectionName(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetConnectionName(GenerateFuzzString(fuzzData, FUZZ_MAX_SMALL_MESSAGE_LENGTH));
}

static void FuzzSetScheduleId(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetScheduleId(fuzzData.ConsumeIntegral<ScheduleId>());
}

static void FuzzSetTriggerReason(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetTriggerReason(GenerateFuzzString(fuzzData, FUZZ_MAX_SMALL_MESSAGE_LENGTH));
}

static void FuzzSetTemplateIdList(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetTemplateIdList(GenerateFuzzVector<TemplateId>(fuzzData, FUZZ_MAX_DEVICE_KEY_COUNT));
}

static void FuzzSetAtl(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetAtl(fuzzData.ConsumeIntegral<Atl>());
}

static void FuzzSetBindingId(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetBindingId(fuzzData.ConsumeIntegral<BindingId>());
}

static void FuzzSetContextId(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetContextId(fuzzData.ConsumeIntegral<uint64_t>());
}

static void FuzzSetSuccessAuthType(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetSuccessAuthType(fuzzData.ConsumeIntegral<int32_t>());
}

static void FuzzSetAlgorithmList(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetAlgorithmList(GenerateFuzzVector<uint16_t>(fuzzData, FUZZ_MAX_CAPABILITIES_COUNT));
}

static void FuzzSetSelectedAlgorithm(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetSelectedAlgorithm(fuzzData.ConsumeIntegral<uint16_t>());
}

static void FuzzSetEsl(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetEsl(fuzzData.ConsumeIntegral<int32_t>());
}

static void FuzzSetProtocolIdList(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetProtocolIdList(GenerateFuzzVector<uint16_t>(fuzzData, FUZZ_MAX_PROTOCOLS_COUNT));
}

static void FuzzSetCapabilityList(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetCapabilityList(GenerateFuzzVector<uint16_t>(fuzzData, FUZZ_MAX_CAPABILITIES_COUNT));
}

static void FuzzSetSelectedProtocolIdList(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetSelectedProtocolIdList(GenerateFuzzVector<uint16_t>(fuzzData, FUZZ_MAX_PROTOCOLS_COUNT));
}

static void FuzzSetSecureProtocolId(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetSecureProtocolId(fuzzData.ConsumeIntegral<uint16_t>());
}

static void FuzzAddTemplateAuthResult(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    collector.AddTemplateAuthResult(templateId, GenerateFuzzResultCode(fuzzData));
}

static void FuzzSetSuccessTemplateId(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.SetSuccessTemplateId(fuzzData.ConsumeIntegral<TemplateId>());
}

static void FuzzTracerOperations(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    // TimingTracer tolerates arbitrary call ordering (Start is idempotent, every other entry is
    // a no-op until Start is called), so a random sequence here cannot corrupt state.
    collector.Start();
    collector.Mark(fuzzData.ConsumeIntegral<StageId>());
    StageId waitId = fuzzData.ConsumeIntegral<StageId>();
    collector.EnterWait(waitId);
    collector.ExitWait(waitId);
    collector.Mark(fuzzData.ConsumeIntegral<StageId>());
}

static void FuzzGetExtraInfo(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    (void)collector.GetExtraInfo();
    (void)collector.GetTotalTime();
    (void)collector.GetLocalTime();
    (void)fuzzData;
}

static void FuzzReport(InteractionEventCollector &collector, FuzzedDataProvider &fuzzData)
{
    collector.Report(GenerateFuzzResultCode(fuzzData));
}

static const CollectorFuzzFunction g_fuzzFuncs[] = {
    FuzzSetHostUserId,
    FuzzSetCompanionUserId,
    FuzzSetConnectionName,
    FuzzSetScheduleId,
    FuzzSetTriggerReason,
    FuzzSetTemplateIdList,
    FuzzSetAtl,
    FuzzSetBindingId,
    FuzzSetContextId,
    FuzzSetSuccessAuthType,
    FuzzSetAlgorithmList,
    FuzzSetSelectedAlgorithm,
    FuzzSetEsl,
    FuzzSetProtocolIdList,
    FuzzSetCapabilityList,
    FuzzSetSelectedProtocolIdList,
    FuzzSetSecureProtocolId,
    FuzzAddTemplateAuthResult,
    FuzzSetSuccessTemplateId,
    FuzzTracerOperations,
    FuzzGetExtraInfo,
    FuzzReport,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(CollectorFuzzFunction);

void FuzzInteractionEventCollector(FuzzedDataProvider &fuzzData)
{
    std::string requestType = GenerateFuzzString(fuzzData, FUZZ_MAX_SMALL_MESSAGE_LENGTH);
    InteractionEventCollector collector(requestType);

    // Exercise every operation once in deterministic order.
    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](collector, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](collector, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzInteractionEventCollector)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
