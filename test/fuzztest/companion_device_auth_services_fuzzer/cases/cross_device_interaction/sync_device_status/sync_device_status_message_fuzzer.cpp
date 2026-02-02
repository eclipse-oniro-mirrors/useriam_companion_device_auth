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
#include "sync_device_status_message.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
}

using SyncDeviceStatusMessageFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

constexpr uint32_t TEST_VAL32 = 32;
constexpr int32_t INT32_10 = 10;

static void FuzzEncodeSyncDeviceStatusRequest(FuzzedDataProvider &fuzzData)
{
    SyncDeviceStatusRequest request;
    uint8_t protoListSize = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_10);
    for (uint8_t j = 0; j < protoListSize; ++j) {
        ProtocolId pid = static_cast<ProtocolId>(fuzzData.ConsumeIntegral<uint32_t>());
        request.protocolIdList.push_back(pid);
    }
    uint8_t capListSize = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_10);
    for (uint8_t j = 0; j < capListSize; ++j) {
        Capability cap = static_cast<Capability>(fuzzData.ConsumeIntegral<uint32_t>());
        request.capabilityList.push_back(cap);
    }
    request.hostDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    request.hostDeviceKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    request.hostDeviceKey.deviceUserId = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t testVal32 = TEST_VAL32;
    request.salt = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, testVal32));
    request.challenge = fuzzData.ConsumeIntegral<uint64_t>();

    Attributes attr;
    EncodeSyncDeviceStatusRequest(request, attr);
}

static void FuzzDecodeSyncDeviceStatusRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto requestOpt = DecodeSyncDeviceStatusRequest(attr);
    (void)requestOpt;
}

static void FuzzEncodeSyncDeviceStatusReply(FuzzedDataProvider &fuzzData)
{
    SyncDeviceStatusReply reply;
    reply.result = static_cast<ResultCode>(fuzzData.ConsumeIntegralInRange<uint32_t>(
        static_cast<uint32_t>(ResultCode::SUCCESS), static_cast<uint32_t>(ResultCode::GENERAL_ERROR)));
    uint8_t protoListSize = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_10);
    for (uint8_t j = 0; j < protoListSize; ++j) {
        ProtocolId pid = static_cast<ProtocolId>(fuzzData.ConsumeIntegral<uint32_t>());
        reply.protocolIdList.push_back(pid);
    }
    uint8_t capListSize = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_10);
    for (uint8_t j = 0; j < capListSize; ++j) {
        Capability cap = static_cast<Capability>(fuzzData.ConsumeIntegral<uint32_t>());
        reply.capabilityList.push_back(cap);
    }
    reply.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint32_t>());
    reply.companionDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    reply.companionDeviceKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    reply.companionDeviceKey.deviceUserId = fuzzData.ConsumeIntegral<int32_t>();
    reply.deviceUserName = GenerateFuzzString(fuzzData, TEST_VAL64);
    reply.companionCheckResponse =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    Attributes attr;
    EncodeSyncDeviceStatusReply(reply, attr);
}

static void FuzzDecodeSyncDeviceStatusReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto replyOpt = DecodeSyncDeviceStatusReply(attr);
    (void)replyOpt;
}

static const SyncDeviceStatusMessageFuzzFunction g_fuzzFuncs[] = {
    FuzzEncodeSyncDeviceStatusRequest,
    FuzzDecodeSyncDeviceStatusRequest,
    FuzzEncodeSyncDeviceStatusReply,
    FuzzDecodeSyncDeviceStatusReply,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SyncDeviceStatusMessageFuzzFunction);

void FuzzSyncDeviceStatusMessage(FuzzedDataProvider &fuzzData)
{
    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData);
    }

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzSyncDeviceStatusMessage)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
