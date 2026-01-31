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

#ifndef COMPANION_DEVICE_AUTH_FFI_UTIL_H
#define COMPANION_DEVICE_AUTH_FFI_UTIL_H

#include <cstdint>
#include <string>
#include <vector>

#include "companion_device_auth_ffi.h"
#include "security_agent.h"
#include "service_common.h"

#undef LOG_TAG
#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
bool EncodeDeviceKey(const DeviceKey &key, DeviceKeyFfi &ffi);
bool DecodeDeviceKey(const DeviceKeyFfi &ffi, DeviceKey &key);
bool EncodePersistedCompanionStatus(const PersistedCompanionStatus &status, PersistedCompanionStatusFfi &ffi);
bool DecodePersistedCompanionStatus(const PersistedCompanionStatusFfi &ffi, PersistedCompanionStatus &status);
bool DecodePersistedCompanionStatusList(const CompanionStatusArrayFfi &ffi,
    std::vector<PersistedCompanionStatus> &list);
bool DecodePersistedHostBindingStatus(const PersistedHostBindingStatusFfi &ffi, PersistedHostBindingStatus &status);
bool DecodePersistedHostBindingStatusList(const HostBindingStatusArrayFfi &ffi,
    std::vector<PersistedHostBindingStatus> &list);

bool DecodeExecutorInfo(const GetExecutorInfoOutputFfi &ffi, SecureExecutorInfo &info);

bool EncodeHostRegisterFinishInput(const RegisterFinishInput &input, HostRegisterFinishInputFfi &ffi);

bool EncodeHostEndCompanionCheckInput(const HostEndCompanionCheckInput &input, HostEndCompanionCheckInputFfi &ffi);
bool EncodeHostGetInitKeyNegotiationInput(const HostGetInitKeyNegotiationRequestInput &input,
    HostGetInitKeyNegotiationInputFfi &ffi);
bool DecodeHostInitKeyNegotiationOutput(const HostGetInitKeyNegotiationOutputFfi &ffi,
    HostGetInitKeyNegotiationRequestOutput &output);

bool EncodeHostBeginAddCompanionInput(const HostBeginAddCompanionInput &input, HostBeginAddCompanionInputFfi &ffi);
bool DecodeHostBeginAddCompanionOutput(const HostBeginAddCompanionOutputFfi &ffi, HostBeginAddCompanionOutput &output);
bool EncodeHostEndAddCompanionInput(const HostEndAddCompanionInput &input, HostEndAddCompanionInputFfi &ffi);
bool DecodeHostEndAddCompanionOutput(const HostEndAddCompanionOutputFfi &ffi, HostEndAddCompanionOutput &output);

bool EncodeHostPreIssueTokenInput(const HostPreIssueTokenInput &input, HostPreIssueTokenInputFfi &ffi);
bool DecodeHostPreIssueTokenOutput(const HostPreIssueTokenOutputFfi &ffi, HostPreIssueTokenOutput &output);
bool EncodeHostBeginIssueTokenInput(const HostBeginIssueTokenInput &input, HostBeginIssueTokenInputFfi &ffi);
bool DecodeHostBeginIssueTokenOutput(const HostBeginIssueTokenOutputFfi &ffi, HostBeginIssueTokenOutput &output);
bool EncodeHostEndIssueTokenInput(const HostEndIssueTokenInput &input, HostEndIssueTokenInputFfi &ffi);
bool DecodeHostEndIssueTokenOutput(const HostEndIssueTokenOutputFfi &ffi, Atl &atl);

bool EncodeHostBeginTokenAuthInput(const HostBeginTokenAuthInput &input, HostBeginTokenAuthInputFfi &ffi);
bool DecodeHostBeginTokenAuthOutput(const HostBeginTokenAuthOutputFfi &ffi, HostBeginTokenAuthOutput &output);
bool EncodeHostEndTokenAuthInput(const HostEndTokenAuthInput &input, HostEndTokenAuthInputFfi &ffi);
bool DecodeHostEndTokenAuthOutput(const HostEndTokenAuthOutputFfi &ffi, HostEndTokenAuthOutput &output);

bool EncodeHostUpdateCompanionStatusInput(const HostUpdateCompanionStatusInput &input,
    HostUpdateCompanionStatusInputFfi &ffi);
bool EncodeHostUpdateCompanionEnabledBusinessIdsInput(const HostUpdateCompanionEnabledBusinessIdsInput &input,
    HostUpdateCompanionEnabledBusinessIdsInputFfi &ffi);

struct HostCheckTemplateEnrolledInput;
struct HostCheckTemplateEnrolledOutput;
bool EncodeHostCheckTemplateEnrolledInput(const HostCheckTemplateEnrolledInput &input,
    HostCheckTemplateEnrolledInputFfi &ffi);
bool DecodeHostCheckTemplateEnrolledOutput(const HostCheckTemplateEnrolledOutputFfi &ffi,
    HostCheckTemplateEnrolledOutput &output);

bool EncodeHostBeginDelegateAuthInput(const HostBeginDelegateAuthInput &input, HostBeginDelegateAuthInputFfi &ffi);
bool DecodeHostBeginDelegateAuthOutput(const HostBeginDelegateAuthOutputFfi &ffi, HostBeginDelegateAuthOutput &output);
bool EncodeHostEndDelegateAuthInput(const HostEndDelegateAuthInput &input, HostEndDelegateAuthInputFfi &ffi);
bool DecodeHostEndDelegateAuthOutput(const HostEndDelegateAuthOutputFfi &ffi, HostEndDelegateAuthOutput &output);

bool EncodeHostProcessPreObtainTokenInput(const HostProcessPreObtainTokenInput &input,
    HostProcessPreObtainTokenInputFfi &ffi);
bool DecodeHostProcessPreObtainTokenOutput(const HostProcessPreObtainTokenOutputFfi &ffi, std::vector<uint8_t> &reply);
bool EncodeHostProcessObtainTokenInput(const HostProcessObtainTokenInput &input, HostProcessObtainTokenInputFfi &ffi);
bool DecodeHostProcessObtainTokenOutput(const HostProcessObtainTokenOutputFfi &ffi, std::vector<uint8_t> &reply,
    Atl &atl);

bool EncodeHostUpdateTokenInput(const HostUpdateTokenInput &input, HostUpdateTokenInputFfi &ffi);
bool DecodeHostUpdateTokenOutput(const HostUpdateTokenOutputFfi &ffi, HostUpdateTokenOutput &output);

// Companion operations
bool EncodeCompanionProcessCheckInput(const CompanionProcessCheckInput &input, CompanionProcessCheckInputFfi &ffi);
bool DecodeCompanionProcessCheckOutput(const CompanionProcessCheckOutputFfi &ffi, CompanionProcessCheckOutput &output);

bool EncodeCompanionInitKeyNegotiationInput(const CompanionInitKeyNegotiationInput &input,
    CompanionInitKeyNegotiationInputFfi &ffi);
bool DecodeCompanionInitKeyNegotiationOutput(const CompanionInitKeyNegotiationOutputFfi &ffi,
    CompanionInitKeyNegotiationOutput &output);

bool EncodeCompanionBeginAddHostBindingInput(const CompanionBeginAddHostBindingInput &input,
    CompanionBeginAddHostBindingInputFfi &ffi);
bool DecodeCompanionBeginAddHostBindingOutput(const CompanionBeginAddHostBindingOutputFfi &ffi,
    CompanionBeginAddHostBindingOutput &output);
bool EncodeCompanionEndAddHostBindingInput(const CompanionEndAddHostBindingInput &input,
    CompanionEndAddHostBindingInputFfi &ffi);
bool DecodeCompanionEndAddHostBindingOutput(const CompanionEndAddHostBindingOutputFfi &ffi,
    CompanionEndAddHostBindingOutput &output);

bool EncodeCompanionPreIssueTokenInput(const CompanionPreIssueTokenInput &input, CompanionPreIssueTokenInputFfi &ffi);
bool DecodeCompanionPreIssueTokenOutput(const CompanionPreIssueTokenOutputFfi &ffi,
    CompanionPreIssueTokenOutput &output);
bool EncodeCompanionProcessIssueTokenInput(const CompanionProcessIssueTokenInput &input,
    CompanionProcessIssueTokenInputFfi &ffi);
bool DecodeCompanionProcessIssueTokenOutput(const CompanionProcessIssueTokenOutputFfi &ffi,
    CompanionProcessIssueTokenOutput &output);

bool EncodeCompanionProcessTokenAuthInput(const CompanionProcessTokenAuthInput &input,
    CompanionProcessTokenAuthInputFfi &ffi);
bool DecodeCompanionProcessTokenAuthOutput(const CompanionProcessTokenAuthOutputFfi &ffi,
    CompanionProcessTokenAuthOutput &output);

bool EncodeCompanionBeginDelegateAuthInput(const CompanionDelegateAuthBeginInput &input,
    CompanionBeginDelegateAuthInputFfi &ffi);
bool DecodeCompanionBeginDelegateAuthOutput(const CompanionBeginDelegateAuthOutputFfi &ffi,
    CompanionDelegateAuthBeginOutput &output);
bool EncodeCompanionEndDelegateAuthInput(const CompanionDelegateAuthEndInput &input,
    CompanionEndDelegateAuthInputFfi &ffi);
bool DecodeCompanionEndDelegateAuthOutput(const CompanionEndDelegateAuthOutputFfi &ffi,
    CompanionDelegateAuthEndOutput &output);

bool EncodeCompanionBeginObtainTokenInput(const CompanionBeginObtainTokenInput &input,
    CompanionBeginObtainTokenInputFfi &ffi);
bool DecodeCompanionBeginObtainTokenOutput(const CompanionBeginObtainTokenOutputFfi &ffi, std::vector<uint8_t> &reply);
bool EncodeCompanionEndObtainTokenInput(const CompanionEndObtainTokenInput &input,
    CompanionEndObtainTokenInputFfi &ffi);

// Event and common output structures
struct Event {
    uint64_t time;
    std::string fileName;
    uint32_t lineNumber;
    int32_t eventType;
    std::string eventInfo;
};

struct CommonOutput {
    int32_t result;
    bool hasFatalError;
    std::vector<Event> events;
};

bool DecodeEvent(const EventFfi &ffi, Event &event);
bool DecodeEventArray(const EventArrayFfi &ffi, std::vector<Event> &events);
bool DecodeCommonOutput(const CommonOutputFfi &ffi, CommonOutput &output);
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FFI_UTIL_H
