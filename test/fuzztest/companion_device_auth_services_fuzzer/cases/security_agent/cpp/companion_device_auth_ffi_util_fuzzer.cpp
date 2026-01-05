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

#include "companion_device_auth_ffi_util.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const uint32_t TEST_VAL256 = 256;
const uint32_t TEST_VAL64 = 64;
const uint32_t TEST_VAL10 = 10;
const uint32_t TEST_VAL16 = 16;
const uint32_t TEST_VAL1024 = 1024;
}

using FuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzDecodeDeviceKey(FuzzedDataProvider &fuzzData)
{
    DeviceKeyFfi ffi;
    ffi.deviceIdType = fuzzData.ConsumeIntegral<uint32_t>();
    ffi.deviceId.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL64);
    for (uint32_t i = 0; i < ffi.deviceId.len && i < TEST_VAL64; ++i) {
        ffi.deviceId.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }
    ffi.userId = fuzzData.ConsumeIntegral<uint32_t>();

    DeviceKey key;
    (void)DecodeDeviceKey(ffi, key);
}

static void FuzzEncodeDeviceKey(FuzzedDataProvider &fuzzData)
{
    DeviceKey key = GenerateFuzzDeviceKey(fuzzData);
    DeviceKeyFfi ffi;
    (void)EncodeDeviceKey(key, ffi);
}

static void FuzzDecodePersistedCompanionStatus(FuzzedDataProvider &fuzzData)
{
    PersistedCompanionStatusFfi ffi;
    ffi.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    ffi.hostUserId = fuzzData.ConsumeIntegral<int32_t>();
    ffi.addedTime = fuzzData.ConsumeIntegral<uint64_t>();
    ffi.secureProtocolId = fuzzData.ConsumeIntegral<uint16_t>();
    ffi.isValid = fuzzData.ConsumeBool();

    // companionDeviceKey
    ffi.companionDeviceKey.deviceIdType = fuzzData.ConsumeIntegral<uint32_t>();
    ffi.companionDeviceKey.deviceId.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL64);
    for (uint32_t i = 0; i < ffi.companionDeviceKey.deviceId.len && i < TEST_VAL64; ++i) {
        ffi.companionDeviceKey.deviceId.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }
    ffi.companionDeviceKey.userId = fuzzData.ConsumeIntegral<uint32_t>();

    // enabledBusinessIds
    ffi.enabledBusinessIds.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL16);
    for (uint32_t i = 0; i < ffi.enabledBusinessIds.len && i < TEST_VAL16; ++i) {
        ffi.enabledBusinessIds.data[i] = fuzzData.ConsumeIntegral<uint32_t>();
    }

    // deviceModel
    ffi.deviceModel.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL64);
    for (uint32_t i = 0; i < ffi.deviceModel.len && i < TEST_VAL64; ++i) {
        ffi.deviceModel.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    // deviceUserName
    ffi.deviceUserName.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL64);
    for (uint32_t i = 0; i < ffi.deviceUserName.len && i < TEST_VAL64; ++i) {
        ffi.deviceUserName.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    // deviceName
    ffi.deviceName.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL64);
    for (uint32_t i = 0; i < ffi.deviceName.len && i < TEST_VAL64; ++i) {
        ffi.deviceName.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    PersistedCompanionStatus status;
    (void)DecodePersistedCompanionStatus(ffi, status);
}

static void FuzzEncodePersistedCompanionStatus(FuzzedDataProvider &fuzzData)
{
    PersistedCompanionStatus status;
    status.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    status.hostUserId = fuzzData.ConsumeIntegral<int32_t>();
    status.addedTime = fuzzData.ConsumeIntegral<uint64_t>();
    status.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    status.isValid = fuzzData.ConsumeBool();
    status.companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    status.deviceModelInfo = GenerateFuzzString(fuzzData, TEST_VAL64);
    status.deviceUserName = GenerateFuzzString(fuzzData, TEST_VAL64);
    status.deviceName = GenerateFuzzString(fuzzData, TEST_VAL64);

    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, TEST_VAL16);
    for (uint8_t i = 0; i < count; ++i) {
        status.enabledBusinessIds.push_back(fuzzData.ConsumeIntegral<uint32_t>());
    }

    PersistedCompanionStatusFfi ffi;
    (void)EncodePersistedCompanionStatus(status, ffi);
}

static void FuzzDecodePersistedCompanionStatusList(FuzzedDataProvider &fuzzData)
{
    CompanionStatusArrayFfi ffi;
    ffi.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL10);

    for (uint32_t i = 0; i < ffi.len && i < TEST_VAL10; ++i) {
        auto &item = ffi.data[i];
        item.templateId = fuzzData.ConsumeIntegral<uint64_t>();
        item.hostUserId = fuzzData.ConsumeIntegral<int32_t>();
        item.addedTime = fuzzData.ConsumeIntegral<uint64_t>();
        item.secureProtocolId = fuzzData.ConsumeIntegral<uint16_t>();
        item.isValid = fuzzData.ConsumeBool();
        item.companionDeviceKey.deviceIdType = fuzzData.ConsumeIntegral<uint32_t>();
        item.companionDeviceKey.deviceId.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL64);
        for (uint32_t j = 0; j < item.companionDeviceKey.deviceId.len && j < TEST_VAL64; ++j) {
            item.companionDeviceKey.deviceId.data[j] = fuzzData.ConsumeIntegral<uint8_t>();
        }
        item.companionDeviceKey.userId = fuzzData.ConsumeIntegral<uint32_t>();
    }

    std::vector<PersistedCompanionStatus> list;
    (void)DecodePersistedCompanionStatusList(ffi, list);
}

static void FuzzDecodeExecutorInfo(FuzzedDataProvider &fuzzData)
{
    GetExecutorInfoOutputFfi ffi;
    ffi.esl = fuzzData.ConsumeIntegral<uint32_t>();
    ffi.maxTemplateAcl = fuzzData.ConsumeIntegral<uint32_t>();
    ffi.publicKey.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL256);
    for (uint32_t i = 0; i < ffi.publicKey.len && i < TEST_VAL256; ++i) {
        ffi.publicKey.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    SecureExecutorInfo info;
    (void)DecodeExecutorInfo(ffi, info);
}

static void FuzzDecodeEventArray(FuzzedDataProvider &fuzzData)
{
    EventArrayFfi ffi;
    ffi.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL10);

    for (uint32_t i = 0; i < ffi.len && i < TEST_VAL10; ++i) {
        auto &event = ffi.data[i];
        event.time = fuzzData.ConsumeIntegral<uint64_t>();
        event.fileName.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL64);
        for (uint32_t j = 0; j < event.fileName.len && j < TEST_VAL64; ++j) {
            event.fileName.data[j] = fuzzData.ConsumeIntegral<uint8_t>();
        }
        event.lineNumber = fuzzData.ConsumeIntegral<uint32_t>();
        event.eventType = fuzzData.ConsumeIntegral<int32_t>();
        event.eventInfo.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL256);
        for (uint32_t j = 0; j < event.eventInfo.len && j < TEST_VAL256; ++j) {
            event.eventInfo.data[j] = fuzzData.ConsumeIntegral<uint8_t>();
        }
    }

    std::vector<Event> events;
    (void)DecodeEventArray(ffi, events);
}

static void FuzzDecodeCompanionBeginAddHostBindingOutput(FuzzedDataProvider &fuzzData)
{
    CompanionBeginAddHostBindingOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }
    ffi.bindingId = fuzzData.ConsumeIntegral<int32_t>();
    // Skip bindingStatus for simplicity in fuzzer

    CompanionBeginAddHostBindingOutput output;
    (void)DecodeCompanionBeginAddHostBindingOutput(ffi, output);
}

static void FuzzDecodeCompanionEndAddHostBindingOutput(FuzzedDataProvider &fuzzData)
{
    CompanionEndAddHostBindingOutputFfi ffi;
    ffi.bindingId = fuzzData.ConsumeIntegral<int32_t>();

    CompanionEndAddHostBindingOutput output;
    (void)DecodeCompanionEndAddHostBindingOutput(ffi, output);
}

static void FuzzDecodeCompanionInitKeyNegotiationOutput(FuzzedDataProvider &fuzzData)
{
    CompanionInitKeyNegotiationOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    CompanionInitKeyNegotiationOutput output;
    (void)DecodeCompanionInitKeyNegotiationOutput(ffi, output);
}

static void FuzzDecodeCompanionPreIssueTokenOutput(FuzzedDataProvider &fuzzData)
{
    CompanionPreIssueTokenOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    CompanionPreIssueTokenOutput output;
    (void)DecodeCompanionPreIssueTokenOutput(ffi, output);
}

static void FuzzDecodeCompanionProcessIssueTokenOutput(FuzzedDataProvider &fuzzData)
{
    CompanionProcessIssueTokenOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    CompanionProcessIssueTokenOutput output;
    (void)DecodeCompanionProcessIssueTokenOutput(ffi, output);
}

static void FuzzDecodeCompanionProcessTokenAuthOutput(FuzzedDataProvider &fuzzData)
{
    CompanionProcessTokenAuthOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    CompanionProcessTokenAuthOutput output;
    (void)DecodeCompanionProcessTokenAuthOutput(ffi, output);
}

static void FuzzDecodeCompanionBeginDelegateAuthOutput(FuzzedDataProvider &fuzzData)
{
    CompanionBeginDelegateAuthOutputFfi ffi;
    ffi.challenge = fuzzData.ConsumeIntegral<uint64_t>();
    ffi.atl = fuzzData.ConsumeIntegral<int32_t>();

    CompanionDelegateAuthBeginOutput output;
    (void)DecodeCompanionBeginDelegateAuthOutput(ffi, output);
}

static void FuzzDecodeCompanionEndDelegateAuthOutput(FuzzedDataProvider &fuzzData)
{
    CompanionEndDelegateAuthOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    CompanionDelegateAuthEndOutput output;
    (void)DecodeCompanionEndDelegateAuthOutput(ffi, output);
}

static void FuzzDecodeCompanionBeginObtainTokenOutput(FuzzedDataProvider &fuzzData)
{
    CompanionBeginObtainTokenOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    std::vector<uint8_t> reply;
    (void)DecodeCompanionBeginObtainTokenOutput(ffi, reply);
}

static void FuzzDecodeCompanionProcessCheckOutput(FuzzedDataProvider &fuzzData)
{
    CompanionProcessCheckOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    CompanionProcessCheckOutput output;
    (void)DecodeCompanionProcessCheckOutput(ffi, output);
}

// Host operations - Priority 1 improvements
static void FuzzDecodeHostInitKeyNegotiationOutput(FuzzedDataProvider &fuzzData)
{
    HostGetInitKeyNegotiationOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    HostGetInitKeyNegotiationRequestOutput output;
    (void)DecodeHostInitKeyNegotiationOutput(ffi, output);
}

static void FuzzDecodeHostBeginAddCompanionOutput(FuzzedDataProvider &fuzzData)
{
    HostBeginAddCompanionOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    HostBeginAddCompanionOutput output;
    (void)DecodeHostBeginAddCompanionOutput(ffi, output);
}

static void FuzzDecodeHostEndAddCompanionOutput(FuzzedDataProvider &fuzzData)
{
    HostEndAddCompanionOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    HostEndAddCompanionOutput output;
    (void)DecodeHostEndAddCompanionOutput(ffi, output);
}

static void FuzzDecodeHostPreIssueTokenOutput(FuzzedDataProvider &fuzzData)
{
    HostPreIssueTokenOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    HostPreIssueTokenOutput output;
    (void)DecodeHostPreIssueTokenOutput(ffi, output);
}

static void FuzzDecodeHostBeginIssueTokenOutput(FuzzedDataProvider &fuzzData)
{
    HostBeginIssueTokenOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    HostBeginIssueTokenOutput output;
    (void)DecodeHostBeginIssueTokenOutput(ffi, output);
}

static void FuzzDecodeHostEndIssueTokenOutput(FuzzedDataProvider &fuzzData)
{
    HostEndIssueTokenOutputFfi ffi;
    // This struct only has atl field
    ffi.atl = fuzzData.ConsumeIntegral<int32_t>();

    Atl atl;
    (void)DecodeHostEndIssueTokenOutput(ffi, atl);
}

static void FuzzDecodeHostBeginTokenAuthOutput(FuzzedDataProvider &fuzzData)
{
    HostBeginTokenAuthOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    HostBeginTokenAuthOutput output;
    (void)DecodeHostBeginTokenAuthOutput(ffi, output);
}

static void FuzzDecodeHostEndTokenAuthOutput(FuzzedDataProvider &fuzzData)
{
    HostEndTokenAuthOutputFfi ffi;
    // Note: This struct uses fwkMessage instead of secMessage
    ffi.fwkMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.fwkMessage.len && i < TEST_VAL1024; ++i) {
        ffi.fwkMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    HostEndTokenAuthOutput output;
    (void)DecodeHostEndTokenAuthOutput(ffi, output);
}

static void FuzzDecodeHostBeginDelegateAuthOutput(FuzzedDataProvider &fuzzData)
{
    HostBeginDelegateAuthOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    HostBeginDelegateAuthOutput output;
    (void)DecodeHostBeginDelegateAuthOutput(ffi, output);
}

static void FuzzDecodeHostEndDelegateAuthOutput(FuzzedDataProvider &fuzzData)
{
    HostEndDelegateAuthOutputFfi ffi;
    // Note: This struct uses fwkMessage instead of secMessage
    ffi.fwkMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.fwkMessage.len && i < TEST_VAL1024; ++i) {
        ffi.fwkMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    HostEndDelegateAuthOutput output;
    (void)DecodeHostEndDelegateAuthOutput(ffi, output);
}

static void FuzzDecodeHostProcessPreObtainTokenOutput(FuzzedDataProvider &fuzzData)
{
    HostProcessPreObtainTokenOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    std::vector<uint8_t> reply;
    (void)DecodeHostProcessPreObtainTokenOutput(ffi, reply);
}

static void FuzzDecodeHostProcessObtainTokenOutput(FuzzedDataProvider &fuzzData)
{
    HostProcessObtainTokenOutputFfi ffi;
    ffi.secMessage.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL1024);
    for (uint32_t i = 0; i < ffi.secMessage.len && i < TEST_VAL1024; ++i) {
        ffi.secMessage.data[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    std::vector<uint8_t> reply;
    Atl atl;
    (void)DecodeHostProcessObtainTokenOutput(ffi, reply, atl);
}

static void FuzzDecodePersistedHostBindingStatusList(FuzzedDataProvider &fuzzData)
{
    HostBindingStatusArrayFfi ffi;
    ffi.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL10);

    for (uint32_t i = 0; i < ffi.len && i < TEST_VAL10; ++i) {
        auto &item = ffi.data[i];
        item.bindingId = fuzzData.ConsumeIntegral<int32_t>();
        item.companionUserId = fuzzData.ConsumeIntegral<int32_t>();
        item.hostDeviceKey.deviceIdType = fuzzData.ConsumeIntegral<uint32_t>();
        item.hostDeviceKey.deviceId.len = fuzzData.ConsumeIntegralInRange<uint32_t>(0, TEST_VAL64);
        for (uint32_t j = 0; j < item.hostDeviceKey.deviceId.len && j < TEST_VAL64; ++j) {
            item.hostDeviceKey.deviceId.data[j] = fuzzData.ConsumeIntegral<uint8_t>();
        }
        item.hostDeviceKey.userId = fuzzData.ConsumeIntegral<uint32_t>();
        item.isTokenValid = fuzzData.ConsumeBool();
    }

    std::vector<PersistedHostBindingStatus> list;
    (void)DecodePersistedHostBindingStatusList(ffi, list);
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzDecodeDeviceKey,
    FuzzEncodeDeviceKey,
    FuzzDecodePersistedCompanionStatus,
    FuzzEncodePersistedCompanionStatus,
    FuzzDecodePersistedCompanionStatusList,
    FuzzDecodeExecutorInfo,
    FuzzDecodeEventArray,
    FuzzDecodeCompanionBeginAddHostBindingOutput,
    FuzzDecodeCompanionEndAddHostBindingOutput,
    FuzzDecodeCompanionInitKeyNegotiationOutput,
    FuzzDecodeCompanionPreIssueTokenOutput,
    FuzzDecodeCompanionProcessIssueTokenOutput,
    FuzzDecodeCompanionProcessTokenAuthOutput,
    FuzzDecodeCompanionBeginDelegateAuthOutput,
    FuzzDecodeCompanionEndDelegateAuthOutput,
    FuzzDecodeCompanionBeginObtainTokenOutput,
    FuzzDecodeCompanionProcessCheckOutput,
    // Host operations - Priority 1 improvements
    FuzzDecodeHostInitKeyNegotiationOutput,
    FuzzDecodeHostBeginAddCompanionOutput,
    FuzzDecodeHostEndAddCompanionOutput,
    FuzzDecodeHostPreIssueTokenOutput,
    FuzzDecodeHostBeginIssueTokenOutput,
    FuzzDecodeHostEndIssueTokenOutput,
    FuzzDecodeHostBeginTokenAuthOutput,
    FuzzDecodeHostEndTokenAuthOutput,
    FuzzDecodeHostBeginDelegateAuthOutput,
    FuzzDecodeHostEndDelegateAuthOutput,
    FuzzDecodeHostProcessPreObtainTokenOutput,
    FuzzDecodeHostProcessObtainTokenOutput,
    FuzzDecodePersistedHostBindingStatusList,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzCompanionDeviceAuthFFIUtil(FuzzedDataProvider &fuzzData)
{
    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData);
    }

    EnsureAllTaskExecuted();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
