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

#include "companion_device_auth_ffi_util.h"

static_assert(MAX_LOG_TRACE_NUM_FFI == OHOS::UserIam::CompanionDeviceAuth::MAX_LOG_TRACE_COUNT,
    "FFI and C++ log trace buffer sizes must match");

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_CDA_FFI_UTIL

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
bool DecodeDeviceKey(const DeviceKeyFfi &ffi, DeviceKey &key)
{
    key.idType = static_cast<DeviceIdType>(ffi.deviceIdType);
    key.deviceUserId = ffi.userId;
    if (!DecodeDataArrayToString(ffi.deviceId, key.deviceId)) {
        return false;
    }
    return true;
}

bool EncodeDeviceKey(const DeviceKey &key, DeviceKeyFfi &ffi)
{
    ffi.deviceIdType = static_cast<int32_t>(key.idType);
    ffi.userId = key.deviceUserId;
    return EncodeStringToDataArray(key.deviceId, ffi.deviceId, "device ID");
}

bool DecodePersistedCompanionStatus(const PersistedCompanionStatusFfi &ffi, PersistedCompanionStatus &status)
{
    status.templateId = ffi.templateId;
    status.hostUserId = ffi.hostUserId;

    if (!DecodeDeviceKey(ffi.companionDeviceKey, status.companionDeviceKey)) {
        return false;
    }

    status.deviceType = static_cast<DeviceType>(ffi.deviceType);
    status.isValid = (ffi.isValid != 0);

    if (!FfiArrayToVector(ffi.enabledBusinessIds, status.enabledBusinessIds)) {
        return false;
    }

    status.addedTime = ffi.addedTime;

    if (!DecodeDataArrayToString(ffi.deviceModelInfo, status.deviceModelInfo)) {
        return false;
    }
    if (!DecodeDataArrayToString(ffi.deviceUserName, status.deviceUserName)) {
        return false;
    }
    if (!DecodeDataArrayToString(ffi.deviceName, status.deviceName)) {
        return false;
    }

    return true;
}

bool EncodePersistedCompanionStatus(const PersistedCompanionStatus &status, PersistedCompanionStatusFfi &ffi)
{
    ffi.templateId = status.templateId;
    ffi.hostUserId = status.hostUserId;

    if (!EncodeDeviceKey(status.companionDeviceKey, ffi.companionDeviceKey)) {
        return false;
    }

    ffi.deviceType = static_cast<int32_t>(status.deviceType);
    ffi.isValid = status.isValid ? 1 : 0;

    if (!VectorToFfiArray(status.enabledBusinessIds, ffi.enabledBusinessIds, "enabled business IDs")) {
        return false;
    }

    ffi.addedTime = status.addedTime;

    if (!EncodeStringToDataArray(status.deviceModelInfo, ffi.deviceModelInfo, "device model info") ||
        !EncodeStringToDataArray(status.deviceUserName, ffi.deviceUserName, "device user name") ||
        !EncodeStringToDataArray(status.deviceName, ffi.deviceName, "device name")) {
        return false;
    }

    return true;
}

bool DecodePersistedHostBindingStatus(const PersistedHostBindingStatusFfi &ffi, PersistedHostBindingStatus &status)
{
    status.bindingId = static_cast<uint32_t>(ffi.bindingId);
    status.companionUserId = ffi.companionUserId;
    status.isTokenValid = ffi.isTokenValid;

    return DecodeDeviceKey(ffi.hostDeviceKey, status.hostDeviceKey);
}

bool DecodePersistedCompanionStatusList(const CompanionStatusArrayFfi &ffi, std::vector<PersistedCompanionStatus> &list)
{
    return FfiArrayToVectorWithConvert(ffi, list, DecodePersistedCompanionStatus, "companion status list");
}

bool DecodePersistedHostBindingStatusList(const HostBindingStatusArrayFfi &ffi,
    std::vector<PersistedHostBindingStatus> &list)
{
    return FfiArrayToVectorWithConvert(ffi, list, DecodePersistedHostBindingStatus, "host binding status list");
}

bool DecodeExecutorInfo(const GetExecutorInfoOutputFfi &ffi, SecureExecutorInfo &info)
{
    info.esl = ffi.esl;
    info.maxTemplateAcl = static_cast<uint32_t>(ffi.maxTemplateAcl);

    return DecodeMessageArray(ffi.publicKey, info.publicKey);
}

bool EncodeHostRegisterFinishInput(const RegisterFinishInput &input, HostRegisterFinishInputFfi &ffi)
{
    if (!VectorToFfiArray(input.templateIdList, ffi.templateIds, "template IDs")) {
        return false;
    }

    if (!EncodeMessageArray(input.fwkPublicKey, ffi.publicKey) || !EncodeMessageArray(input.fwkMsg, ffi.fwkMsg)) {
        return false;
    }

    return true;
}

bool EncodeHostBeginCompanionCheckInput(const HostBeginCompanionCheckInput &input, HostBeginCompanionCheckInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.userId = input.userId;
    return true;
}

bool DecodeHostBeginCompanionCheckOutput(const HostBeginCompanionCheckOutputFfi &ffi,
    HostBeginCompanionCheckOutput &output)
{
    if (ffi.salt.len == 0) {
        IAM_LOGE("salt length is zero");
        return false;
    }
    if (!FfiArrayToVector(ffi.salt, output.salt)) {
        IAM_LOGE("failed to decode salt");
        return false;
    }
    output.challenge = ffi.challenge;
    return true;
}

bool EncodeHostEndCompanionCheckInput(const HostEndCompanionCheckInput &input, HostEndCompanionCheckInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.templateId = input.templateId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    if (!VectorToFfiArray(input.protocolVersionList, ffi.protocolList, "protocol list") ||
        !VectorToFfiArray(input.capabilityList, ffi.capabilityList, "capability list")) {
        return false;
    }

    return EncodeMessageArray(input.companionCheckResponse, ffi.secMessage);
}

bool EncodeHostGetInitKeyNegotiationInput(const HostGetInitKeyNegotiationRequestInput &input,
    HostGetInitKeyNegotiationInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);
    return true;
}

bool DecodeHostInitKeyNegotiationOutput(const HostGetInitKeyNegotiationOutputFfi &ffi,
    HostGetInitKeyNegotiationRequestOutput &output)
{
    if (!DecodeMessageArray(ffi.secMessage, output.initKeyNegotiationRequest)) {
        return false;
    }
    return FfiArrayToVector(ffi.algorithmList, output.algorithmList);
}

bool EncodeHostBeginAddCompanionInput(const HostBeginAddCompanionInput &input, HostBeginAddCompanionInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.scheduleId = input.scheduleId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    if (!EncodeDeviceKey(input.hostDeviceKey, ffi.hostDeviceKey) ||
        !EncodeDeviceKey(input.companionDeviceKey, ffi.companionDeviceKey)) {
        return false;
    }

    if (!EncodeMessageArray(input.fwkMsg, ffi.fwkMessage) ||
        !EncodeMessageArray(input.initKeyNegotiationReply, ffi.secMessage)) {
        return false;
    }

    return true;
}

bool DecodeHostBeginAddCompanionOutput(const HostBeginAddCompanionOutputFfi &ffi, HostBeginAddCompanionOutput &output)
{
    if (!DecodeMessageArray(ffi.secMessage, output.addHostBindingRequest)) {
        return false;
    }
    output.selectedAlgorithm = ffi.selectedAlgorithm;
    return true;
}

bool EncodeHostEndAddCompanionInput(const HostEndAddCompanionInput &input, HostEndAddCompanionInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    if (!EncodePersistedCompanionStatus(input.companionStatus, ffi.companionStatus)) {
        return false;
    }

    if (!VectorToFfiArray(input.protocolVersionList, ffi.protocolList, "protocol list") ||
        !VectorToFfiArray(input.capabilityList, ffi.capabilityList, "capability list")) {
        return false;
    }

    return EncodeMessageArray(input.addHostBindingReply, ffi.secMessage);
}

bool DecodeHostEndAddCompanionOutput(const HostEndAddCompanionOutputFfi &ffi, HostEndAddCompanionOutput &output)
{
    output.templateId = ffi.templateId;
    output.atl = ffi.atl;
    output.esl = ffi.esl;
    output.addedTime = ffi.addedTime;
    if (!DecodeMessageArray(ffi.fwkMessage, output.fwkMsg) || !DecodeMessageArray(ffi.secMessage, output.tokenData)) {
        return false;
    }

    return true;
}

bool EncodeHostPreIssueTokenInput(const HostPreIssueTokenInput &input, HostPreIssueTokenInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.templateId = input.templateId;

    return EncodeMessageArray(input.fwkUnlockMsg, ffi.fwkMessage);
}

bool DecodeHostPreIssueTokenOutput(const HostPreIssueTokenOutputFfi &ffi, HostPreIssueTokenOutput &output)
{
    return DecodeMessageArray(ffi.secMessage, output.preIssueTokenRequest);
}

bool EncodeHostBeginIssueTokenInput(const HostBeginIssueTokenInput &input, HostBeginIssueTokenInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.preIssueTokenReply, ffi.secMessage);
}

bool DecodeHostBeginIssueTokenOutput(const HostBeginIssueTokenOutputFfi &ffi, HostBeginIssueTokenOutput &output)
{
    return DecodeMessageArray(ffi.secMessage, output.issueTokenRequest);
}

bool EncodeHostEndIssueTokenInput(const HostEndIssueTokenInput &input, HostEndIssueTokenInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.issueTokenReply, ffi.secMessage);
}

bool DecodeHostEndIssueTokenOutput(const HostEndIssueTokenOutputFfi &ffi, Atl &atl)
{
    atl = ffi.atl;
    return true;
}

bool EncodeHostBeginTokenAuthInput(const HostBeginTokenAuthInput &input, HostBeginTokenAuthInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.scheduleId = input.scheduleId;
    ffi.templateId = input.templateId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.fwkMsg, ffi.fwkMessage);
}

bool DecodeHostBeginTokenAuthOutput(const HostBeginTokenAuthOutputFfi &ffi, HostBeginTokenAuthOutput &output)
{
    return DecodeMessageArray(ffi.secMessage, output.tokenAuthRequest);
}

bool EncodeHostEndTokenAuthInput(const HostEndTokenAuthInput &input, HostEndTokenAuthInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.templateId = input.templateId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.tokenAuthReply, ffi.secMessage);
}

bool DecodeHostEndTokenAuthOutput(const HostEndTokenAuthOutputFfi &ffi, HostEndTokenAuthOutput &output)
{
    return DecodeMessageArray(ffi.fwkMessage, output.fwkMsg);
}

bool EncodeHostUpdateCompanionStatusInput(const HostUpdateCompanionStatusInput &input,
    HostUpdateCompanionStatusInputFfi &ffi)
{
    ffi.templateId = input.templateId;

    if (!EncodeStringToDataArray(input.companionDeviceModelInfo, ffi.deviceModelInfo, "companion device model info") ||
        !EncodeStringToDataArray(input.companionDeviceName, ffi.deviceName, "companion device name") ||
        !EncodeStringToDataArray(input.companionDeviceUserName, ffi.deviceUserName, "companion device user name")) {
        return false;
    }

    return true;
}

bool EncodeHostUpdateCompanionEnabledBusinessIdsInput(const HostUpdateCompanionEnabledBusinessIdsInput &input,
    HostUpdateCompanionEnabledBusinessIdsInputFfi &ffi)
{
    ffi.templateId = input.templateId;

    return VectorToFfiArray(input.enabledBusinessIds, ffi.businessIds, "enabled business IDs");
}

bool EncodeHostSetCompanionInvalidInput(const HostSetCompanionInvalidInput &input, HostSetCompanionInvalidInputFfi &ffi)
{
    ffi.templateId = input.templateId;
    return true;
}

bool EncodeHostCheckTemplateEnrolledInput(const HostCheckTemplateEnrolledInput &input,
    HostCheckTemplateEnrolledInputFfi &ffi)
{
    ffi.templateId = input.templateId;
    return true;
}

bool DecodeHostCheckTemplateEnrolledOutput(const HostCheckTemplateEnrolledOutputFfi &ffi,
    HostCheckTemplateEnrolledOutput &output)
{
    output.enrolled = (ffi.enrolled != 0);
    return true;
}

bool EncodeHostBeginDelegateAuthInput(const HostBeginDelegateAuthInput &input, HostBeginDelegateAuthInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.scheduleId = input.scheduleId;
    ffi.templateId = input.templateId;

    return EncodeMessageArray(input.fwkMsg, ffi.fwkMessage);
}

bool DecodeHostBeginDelegateAuthOutput(const HostBeginDelegateAuthOutputFfi &ffi, HostBeginDelegateAuthOutput &output)
{
    return DecodeMessageArray(ffi.secMessage, output.startDelegateAuthRequest);
}

bool EncodeHostEndDelegateAuthInput(const HostEndDelegateAuthInput &input, HostEndDelegateAuthInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.delegateAuthResult, ffi.secMessage);
}

bool DecodeHostEndDelegateAuthOutput(const HostEndDelegateAuthOutputFfi &ffi, HostEndDelegateAuthOutput &output)
{
    output.authType = static_cast<AuthType>(ffi.authType);
    output.atl = ffi.atl;

    return DecodeMessageArray(ffi.fwkMessage, output.fwkMsg);
}

bool EncodeHostProcessPreObtainTokenInput(const HostProcessPreObtainTokenInput &input,
    HostProcessPreObtainTokenInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.templateId = input.templateId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);
    return true;
}

bool DecodeHostProcessPreObtainTokenOutput(const HostProcessPreObtainTokenOutputFfi &ffi, std::vector<uint8_t> &reply)
{
    return DecodeMessageArray(ffi.secMessage, reply);
}

bool EncodeHostProcessObtainTokenInput(const HostProcessObtainTokenInput &input, HostProcessObtainTokenInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.templateId = input.templateId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.obtainTokenRequest, ffi.secMessage);
}

bool DecodeHostProcessObtainTokenOutput(const HostProcessObtainTokenOutputFfi &ffi, std::vector<uint8_t> &reply,
    Atl &atl)
{
    atl = ffi.atl;
    return DecodeMessageArray(ffi.secMessage, reply);
}

bool EncodeHostUpdateTokenInput(const HostUpdateTokenInput &input, HostUpdateTokenInputFfi &ffi)
{
    ffi.templateId = input.templateId;
    return EncodeMessageArray(input.fwkMsg, ffi.fwkMessage);
}

bool DecodeHostUpdateTokenOutput(const HostUpdateTokenOutputFfi &ffi, HostUpdateTokenOutput &output)
{
    output.needRedistribute = ffi.needRedistribute;
    return true;
}

bool EncodeCompanionProcessCheckInput(const CompanionProcessCheckInput &input, CompanionProcessCheckInputFfi &ffi)
{
    ffi.bindingId = input.bindingId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);
    ffi.challenge = input.challenge;

    if (!VectorToFfiArray(input.protocolList, ffi.protocolList, "protocol list")) {
        return false;
    }

    if (!VectorToFfiArray(input.capabilityList, ffi.capabilityList, "capability list")) {
        return false;
    }

    if (!VectorToFfiArray(input.salt, ffi.salt, "salt")) {
        return false;
    }

    return EncodeMessageArray(input.companionCheckRequest, ffi.secMessage);
}

bool DecodeCompanionProcessCheckOutput(const CompanionProcessCheckOutputFfi &ffi, CompanionProcessCheckOutput &output)
{
    return DecodeMessageArray(ffi.secMessage, output.companionCheckResponse);
}

bool EncodeCompanionInitKeyNegotiationInput(const CompanionInitKeyNegotiationInput &input,
    CompanionInitKeyNegotiationInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    if (!VectorToFfiArray(input.protocolList, ffi.protocolList, "protocol list")) {
        return false;
    }

    if (!VectorToFfiArray(input.capabilityList, ffi.capabilityList, "capability list")) {
        return false;
    }

    if (!EncodeDeviceKey(input.hostDeviceKey, ffi.hostDeviceKey) ||
        !EncodeDeviceKey(input.companionDeviceKey, ffi.companionDeviceKey)) {
        return false;
    }

    return EncodeMessageArray(input.initKeyNegotiationRequest, ffi.secMessage);
}

bool DecodeCompanionInitKeyNegotiationOutput(const CompanionInitKeyNegotiationOutputFfi &ffi,
    CompanionInitKeyNegotiationOutput &output)
{
    if (!DecodeMessageArray(ffi.secMessage, output.initKeyNegotiationReply)) {
        return false;
    }
    if (!FfiArrayToVector(ffi.algorithmList, output.algorithmList)) {
        return false;
    }
    output.selectedAlgorithm = ffi.selectedAlgorithm;
    return true;
}

bool EncodeCompanionBeginAddHostBindingInput(const CompanionBeginAddHostBindingInput &input,
    CompanionBeginAddHostBindingInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.addHostBindingRequest, ffi.secMessage);
}

bool DecodeCompanionBeginAddHostBindingOutput(const CompanionBeginAddHostBindingOutputFfi &ffi,
    CompanionBeginAddHostBindingOutput &output)
{
    if (!DecodeMessageArray(ffi.secMessage, output.addHostBindingReply)) {
        return false;
    }

    if (ffi.replacedBindingId != 0) {
        output.replacedBindingId = ffi.replacedBindingId;
    } else {
        output.replacedBindingId = std::nullopt;
    }

    return DecodePersistedHostBindingStatus(ffi.bindingStatus, output.hostBindingStatus);
}

bool EncodeCompanionEndAddHostBindingInput(const CompanionEndAddHostBindingInput &input,
    CompanionEndAddHostBindingInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.result = static_cast<int32_t>(input.resultCode);
    return EncodeMessageArray(input.tokenData, ffi.secMessage);
}

bool DecodeCompanionEndAddHostBindingOutput(const CompanionEndAddHostBindingOutputFfi &ffi,
    CompanionEndAddHostBindingOutput &output)
{
    output.atl = ffi.atl;
    output.esl = ffi.esl;
    return true;
}

bool EncodeCompanionPreIssueTokenInput(const CompanionPreIssueTokenInput &input, CompanionPreIssueTokenInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.bindingId = input.bindingId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.preIssueTokenRequest, ffi.secMessage);
}

bool DecodeCompanionPreIssueTokenOutput(const CompanionPreIssueTokenOutputFfi &ffi,
    CompanionPreIssueTokenOutput &output)
{
    return DecodeMessageArray(ffi.secMessage, output.preIssueTokenReply);
}

bool EncodeCompanionProcessIssueTokenInput(const CompanionProcessIssueTokenInput &input,
    CompanionProcessIssueTokenInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.issueTokenRequest, ffi.secMessage);
}

bool DecodeCompanionProcessIssueTokenOutput(const CompanionProcessIssueTokenOutputFfi &ffi,
    CompanionProcessIssueTokenOutput &output)
{
    output.atl = ffi.atl;
    return DecodeMessageArray(ffi.secMessage, output.issueTokenReply);
}

bool EncodeCompanionProcessTokenAuthInput(const CompanionProcessTokenAuthInput &input,
    CompanionProcessTokenAuthInputFfi &ffi)
{
    ffi.bindingId = input.bindingId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.tokenAuthRequest, ffi.secMessage);
}

bool DecodeCompanionProcessTokenAuthOutput(const CompanionProcessTokenAuthOutputFfi &ffi,
    CompanionProcessTokenAuthOutput &output)
{
    return DecodeMessageArray(ffi.secMessage, output.tokenAuthReply);
}

bool EncodeCompanionBeginDelegateAuthInput(const CompanionDelegateAuthBeginInput &input,
    CompanionBeginDelegateAuthInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.bindingId = input.bindingId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.startDelegateAuthRequest, ffi.secMessage);
}

bool DecodeCompanionBeginDelegateAuthOutput(const CompanionBeginDelegateAuthOutputFfi &ffi,
    CompanionDelegateAuthBeginOutput &output)
{
    output.challenge = ffi.challenge;
    output.atl = ffi.atl;
    return true;
}

bool EncodeCompanionEndDelegateAuthInput(const CompanionDelegateAuthEndInput &input,
    CompanionEndDelegateAuthInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.result = static_cast<int32_t>(input.resultCode);

    return VectorToFfiArray(input.authToken, ffi.authToken, "auth token");
}

bool DecodeCompanionEndDelegateAuthOutput(const CompanionEndDelegateAuthOutputFfi &ffi,
    CompanionDelegateAuthEndOutput &output)
{
    output.authType = ffi.authType;
    output.atl = ffi.atl;
    return DecodeMessageArray(ffi.secMessage, output.delegateAuthResult);
}

bool EncodeCompanionBeginObtainTokenInput(const CompanionBeginObtainTokenInput &input,
    CompanionBeginObtainTokenInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.bindingId = input.bindingId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    if (!EncodeMessageArray(input.fwkUnlockMsg, ffi.fwkMessage) ||
        !EncodeMessageArray(input.preObtainTokenReply, ffi.secMessage)) {
        return false;
    }

    return true;
}

bool DecodeCompanionBeginObtainTokenOutput(const CompanionBeginObtainTokenOutputFfi &ffi, std::vector<uint8_t> &reply,
    Atl &atl)
{
    atl = ffi.atl;
    return DecodeMessageArray(ffi.secMessage, reply);
}

bool EncodeCompanionEndObtainTokenInput(const CompanionEndObtainTokenInput &input, CompanionEndObtainTokenInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    return EncodeMessageArray(input.obtainTokenReply, ffi.secMessage);
}

bool DecodeEvent(const EventFfi &ffi, Event &event)
{
    event.time = ffi.time;
    event.lineNumber = ffi.lineNumber;
    event.eventType = ffi.eventType;

    if (!DecodeDataArrayToString(ffi.fileName, event.fileName)) {
        return false;
    }
    if (!DecodeDataArrayToString(ffi.eventInfo, event.eventInfo)) {
        return false;
    }

    return true;
}

bool DecodeEventArray(const EventArrayFfi &ffi, std::vector<Event> &events)
{
    return FfiArrayToVectorWithConvert(ffi, events, DecodeEvent, "event array");
}

bool DecodeCommonOutput(const CommonOutputFfi &ffi, CommonOutput &output)
{
    output.result = ffi.result;
    output.hasFatalError = ffi.hasFatalError;

    auto decodeLogTrace = [](const LogTraceEntryFfi &src, LogEntry &dst) -> bool {
        dst = { src.code, src.fileId, src.lineNum };
        return true;
    };
    if (!FfiArrayToVectorWithConvert(ffi.logTrace, output.logTrace, decodeLogTrace, "log trace")) {
        return false;
    }

    return DecodeEventArray(ffi.events, output.events);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
