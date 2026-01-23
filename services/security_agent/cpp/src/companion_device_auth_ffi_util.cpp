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

#include <type_traits>

#include <securec.h>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_safe_arithmetic.h"

#undef LOG_TAG
#define LOG_TAG "DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
template <typename T, size_t N>
bool FixedArrayToVector(const T (&arr)[N], std::vector<T> &vec)
{
    vec.assign(arr, arr + N);
    return true;
}

template <typename T, size_t N>
bool VectorToFixedArray(const std::vector<T> &vec, T (&arr)[N], const char *name)
{
    if (vec.size() != N) {
        IAM_LOGE("Vector size mismatch for %{public}s: %{public}zu != %{public}zu", name, vec.size(), N);
        return false;
    }
    auto copySizeOpt = safe_mul(N, sizeof(T));
    ENSURE_OR_RETURN_VAL(copySizeOpt.has_value(), false);

    if (memcpy_s(arr, sizeof(arr), vec.data(), copySizeOpt.value()) != EOK) {
        IAM_LOGE("Failed to copy %{public}s", name);
        return false;
    }
    return true;
}

template <typename FfiArrayType, typename T>
bool FfiArrayToVector(const FfiArrayType &ffiArr, std::vector<T> &vec)
{
    constexpr size_t maxSize = sizeof(ffiArr.data) / sizeof(ffiArr.data[0]);
    if (ffiArr.len > maxSize) {
        IAM_LOGE("FFI array length exceeds maximum: %{public}u > %{public}zu", ffiArr.len, maxSize);
        return false;
    }

    using ElementType = typename std::remove_reference<decltype(ffiArr.data[0])>::type;

    if constexpr (std::is_same_v<T, uint8_t>) {
        vec.assign(ffiArr.data, ffiArr.data + ffiArr.len);
    } else {
        static_assert(sizeof(T) == sizeof(ElementType),
            "Type size mismatch: FFI array element type and target vector element type must have the same size");

        vec.clear();
        if (ffiArr.len > 0) {
            try {
                vec.reserve(ffiArr.len);
            } catch (...) {
                IAM_LOGE("Failed to reserve memory for vector conversion");
                return false;
            }
            for (uint32_t i = 0; i < ffiArr.len; ++i) {
                vec.push_back(static_cast<T>(ffiArr.data[i]));
            }
        }
    }
    return true;
}

template <typename FfiArrayType, typename T>
bool VectorToFfiArray(const std::vector<T> &vec, FfiArrayType &ffiArr, const char *name)
{
    constexpr size_t maxSize = sizeof(ffiArr.data) / sizeof(ffiArr.data[0]);
    if (vec.size() > maxSize) {
        IAM_LOGE("%{public}s size exceeds maximum: %{public}zu > %{public}zu", name, vec.size(), maxSize);
        return false;
    }
    if (vec.size() > UINT32_MAX) {
        IAM_LOGE("%{public}s size exceeds uint32_t maximum: %{public}zu > %{public}u", name, vec.size(), UINT32_MAX);
        return false;
    }
    ffiArr.len = static_cast<uint32_t>(vec.size());

    using ElementType = typename std::remove_reference<decltype(ffiArr.data[0])>::type;
    if constexpr (std::is_same_v<T, ElementType> && (std::is_integral_v<T> || std::is_enum_v<T>)) {
        if (ffiArr.len > 0) {
            auto copySizeOpt = safe_mul(ffiArr.len, static_cast<uint32_t>(sizeof(ElementType)));
            ENSURE_OR_RETURN_VAL(copySizeOpt.has_value(), false);

            auto bufferSizeOpt = safe_mul(static_cast<uint32_t>(maxSize), static_cast<uint32_t>(sizeof(ElementType)));
            ENSURE_OR_RETURN_VAL(bufferSizeOpt.has_value(), false);

            if (memcpy_s(ffiArr.data, bufferSizeOpt.value(), vec.data(), copySizeOpt.value()) != EOK) {
                IAM_LOGE("Failed to copy %{public}s", name);
                return false;
            }
        }
    } else {
        for (size_t i = 0; i < vec.size(); ++i) {
            ffiArr.data[i] = static_cast<ElementType>(vec[i]);
        }
    }
    return true;
}

template <typename FfiArrayType, typename ItemType, typename ConvertFunc>
bool FfiArrayToVectorWithConvert(const FfiArrayType &ffiArr, std::vector<ItemType> &vec, ConvertFunc convertFunc,
    const char *name)
{
    constexpr size_t maxSize = sizeof(ffiArr.data) / sizeof(ffiArr.data[0]);
    if (ffiArr.len > maxSize) {
        IAM_LOGE("FFI array %{public}s length exceeds maximum: %{public}u > %{public}zu", name, ffiArr.len, maxSize);
        return false;
    }
    vec.clear();
    if (ffiArr.len > 0) {
        try {
            vec.reserve(ffiArr.len);
        } catch (...) {
            IAM_LOGE("Failed to reserve memory for %{public}s conversion", name);
            return false;
        }
        for (uint32_t i = 0; i < ffiArr.len; ++i) {
            ItemType item {};
            if (!convertFunc(ffiArr.data[i], item)) {
                IAM_LOGE("Failed to convert %{public}s at index %{public}u", name, i);
                return false;
            }
            vec.push_back(std::move(item));
        }
    }
    return true;
}

template <typename DataArrayType>
bool DecodeDataArrayToString(const DataArrayType &ffi, std::string &str)
{
    std::vector<uint8_t> vec;
    if (!FfiArrayToVector(ffi, vec)) {
        return false;
    }

    if (vec.empty()) {
        str.clear();
        return true;
    }

    str = std::string(reinterpret_cast<const char *>(vec.data()), vec.size());
    return true;
}

inline bool DecodeMessageArray(const DataArray1024Ffi &ffi, std::vector<uint8_t> &vec)
{
    return FfiArrayToVector(ffi, vec);
}

inline bool EncodeMessageArray(const std::vector<uint8_t> &vec, DataArray1024Ffi &ffi)
{
    return VectorToFfiArray(vec, ffi, "message array");
}

inline bool DecodeMessageArray(const DataArray20000Ffi &ffi, std::vector<uint8_t> &vec)
{
    return FfiArrayToVector(ffi, vec);
}

inline bool EncodeMessageArray(const std::vector<uint8_t> &vec, DataArray20000Ffi &ffi)
{
    return VectorToFfiArray(vec, ffi, "message array");
}

template <typename DataArrayType>
bool EncodeStringToDataArray(const std::string &str, DataArrayType &ffi, const char *name)
{
    std::vector<uint8_t> vec(str.begin(), str.end());
    return VectorToFfiArray(vec, ffi, name);
}
} // namespace
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
    status.addedTime = ffi.addedTime;
    status.secureProtocolId = static_cast<SecureProtocolId>(ffi.secureProtocolId);
    status.isValid = (ffi.isValid != 0);

    if (!DecodeDeviceKey(ffi.companionDeviceKey, status.companionDeviceKey)) {
        return false;
    }

    if (!FfiArrayToVector(ffi.enabledBusinessIds, status.enabledBusinessIds)) {
        return false;
    }

    if (!DecodeDataArrayToString(ffi.deviceModel, status.deviceModelInfo)) {
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
    ffi.addedTime = status.addedTime;
    ffi.secureProtocolId = static_cast<uint16_t>(status.secureProtocolId);
    ffi.isValid = status.isValid ? 1 : 0;

    if (!EncodeDeviceKey(status.companionDeviceKey, ffi.companionDeviceKey)) {
        return false;
    }

    if (!VectorToFfiArray(status.enabledBusinessIds, ffi.enabledBusinessIds, "enabled business IDs")) {
        return false;
    }

    if (!EncodeStringToDataArray(status.deviceModelInfo, ffi.deviceModel, "device model info") ||
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
    return DecodeMessageArray(ffi.secMessage, output.initKeyNegotiationRequest);
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
    return DecodeMessageArray(ffi.secMessage, output.addHostBindingRequest);
}

bool EncodeHostEndAddCompanionInput(const HostEndAddCompanionInput &input, HostEndAddCompanionInputFfi &ffi)
{
    ffi.requestId = input.requestId;
    ffi.secureProtocolId = static_cast<uint16_t>(input.secureProtocolId);

    if (!EncodePersistedCompanionStatus(input.companionStatus, ffi.companionStatus)) {
        return false;
    }

    return EncodeMessageArray(input.addHostBindingReply, ffi.secMessage);
}

bool DecodeHostEndAddCompanionOutput(const HostEndAddCompanionOutputFfi &ffi, HostEndAddCompanionOutput &output)
{
    output.templateId = ffi.templateId;
    output.atl = ffi.atl;
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

    if (!EncodeStringToDataArray(input.companionDeviceName, ffi.deviceName, "companion device name") ||
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

    if (!EncodeDeviceKey(input.hostDeviceKey, ffi.hostDeviceKey) ||
        !EncodeDeviceKey(input.companionDeviceKey, ffi.companionDeviceKey)) {
        return false;
    }

    return EncodeMessageArray(input.initKeyNegotiationRequest, ffi.secMessage);
}

bool DecodeCompanionInitKeyNegotiationOutput(const CompanionInitKeyNegotiationOutputFfi &ffi,
    CompanionInitKeyNegotiationOutput &output)
{
    return DecodeMessageArray(ffi.secMessage, output.initKeyNegotiationReply);
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

    if (ffi.bindingId != 0) {
        output.replacedBindingId = ffi.bindingId;
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
    ;
}

bool DecodeCompanionEndAddHostBindingOutput(const CompanionEndAddHostBindingOutputFfi &ffi,
    CompanionEndAddHostBindingOutput &output)
{
    output.bindingId = ffi.bindingId;
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

bool DecodeCompanionBeginObtainTokenOutput(const CompanionBeginObtainTokenOutputFfi &ffi, std::vector<uint8_t> &reply)
{
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
    if (ffi.len > MAX_EVENT_NUM_FFI) {
        IAM_LOGE("Event count exceeds maximum: %{public}u > %{public}u", ffi.len, MAX_EVENT_NUM_FFI);
        return false;
    }

    events.clear();
    events.reserve(ffi.len);

    for (uint32_t i = 0; i < ffi.len; ++i) {
        Event event {};
        if (!DecodeEvent(ffi.data[i], event)) {
            IAM_LOGE("Failed to convert event at index %{public}u", i);
            return false;
        }
        events.push_back(std::move(event));
    }

    return true;
}

bool DecodeCommonOutput(const CommonOutputFfi &ffi, CommonOutput &output)
{
    output.result = ffi.result;
    output.hasFatalError = ffi.hasFatalError;

    return DecodeEventArray(ffi.events, output.events);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS