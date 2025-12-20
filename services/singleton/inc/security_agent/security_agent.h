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
#ifndef COMPANION_DEVICE_AUTH_SECURITY_AGENT_H
#define COMPANION_DEVICE_AUTH_SECURITY_AGENT_H

#include <memory>
#include <optional>
#include <vector>

#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
// Framework interaction input/output structs
struct SetActiveUserInput {
    UserId userId;
};

struct HostGetExecutorInfoOutput {
    SecureExecutorInfo executorInfo;
};

struct RegisterFinishInput {
    std::vector<int32_t> templateIdList;
    std::vector<uint8_t> fwkPublicKey;
    std::vector<uint8_t> fwkMsg;
};

struct HostGetPersistedCompanionStatusInput {
    UserId userId;
};

struct HostGetPersistedCompanionStatusOutput {
    std::vector<PersistedCompanionStatus> companionStatusList;
};

struct CompanionGetPersistedHostBindingStatusInput {
    UserId userId;
};

struct CompanionGetPersistedHostBindingStatusOutput {
    std::vector<PersistedHostBindingStatus> hostBindingStatusList;
};

// Companion check input/output structs
struct HostBeginCompanionCheckInput {
    RequestId requestId;
};

struct HostBeginCompanionCheckOutput {
    std::vector<uint8_t> salt;
    uint64_t challenge;
};

struct HostEndCompanionCheckInput {
    RequestId requestId;
    TemplateId templateId;
    std::vector<uint16_t> protocolVersionList;
    std::vector<uint16_t> capabilityList;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> companionCheckResponse;
};

struct HostCancelCompanionCheckInput {
    RequestId requestId;
};

struct CompanionProcessCheckInput {
    BindingId bindingId;
    std::vector<uint16_t> capabilityList;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> salt;
    uint64_t challenge;
    std::vector<uint8_t> companionCheckRequest;
};

struct CompanionProcessCheckOutput {
    std::vector<uint8_t> companionCheckResponse;
};

struct CompanionCancelCheckInput {
    RequestId requestId;
};

// Add companion device input/output structs
struct HostGetInitKeyNegotiationRequestInput {
    RequestId requestId;
    SecureProtocolId secureProtocolId;
};

struct HostGetInitKeyNegotiationRequestOutput {
    std::vector<uint8_t> initKeyNegotiationRequest;
};

struct HostBeginAddCompanionInput {
    RequestId requestId;
    ScheduleId scheduleId;
    DeviceKey hostDeviceKey;
    DeviceKey companionDeviceKey;
    std::vector<uint8_t> fwkMsg;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> initKeyNegotiationReply;
};

struct HostBeginAddCompanionOutput {
    std::vector<uint8_t> addHostBindingRequest;
};

struct HostEndAddCompanionInput {
    RequestId requestId;
    PersistedCompanionStatus companionStatus;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> addHostBindingReply;
};

struct HostEndAddCompanionOutput {
    std::vector<uint8_t> fwkMsg;
    TemplateId templateId;
};

struct HostCancelAddCompanionInput {
    RequestId requestId;
};

struct CompanionInitKeyNegotiationInput {
    RequestId requestId;
    SecureProtocolId secureProtocolId;
    DeviceKey companionDeviceKey;
    DeviceKey hostDeviceKey;
    std::vector<uint8_t> initKeyNegotiationRequest;
};

struct CompanionInitKeyNegotiationOutput {
    RequestId requestId;
    std::vector<uint8_t> initKeyNegotiationReply;
};

struct CompanionBeginAddHostBindingInput {
    RequestId requestId;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> addHostBindingRequest;
};

struct CompanionBeginAddHostBindingOutput {
    std::vector<uint8_t> addHostBindingReply;
    std::optional<BindingId> replacedBindingId;
    PersistedHostBindingStatus hostBindingStatus;
};

struct CompanionEndAddHostBindingInput {
    RequestId requestId;
    ResultCode resultCode;
};

struct CompanionEndAddHostBindingOutput {
    BindingId bindingId;
};

struct HostRemoveCompanionInput {
    TemplateId templateId;
};

struct HostRemoveCompanionOutput {
    UserId userId;
    DeviceKey companionDeviceKey;
};

struct CompanionRemoveHostBindingInput {
    BindingId bindingId;
};

// Delegate auth input/output structs
struct HostBeginDelegateAuthInput {
    RequestId requestId;
    ScheduleId scheduleId;
    TemplateId templateId;
    std::vector<uint8_t> fwkMsg;
};

struct HostBeginDelegateAuthOutput {
    std::vector<uint8_t> startDelegateAuthRequest;
};

struct HostEndDelegateAuthInput {
    RequestId requestId;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> delegateAuthResult;
};

struct HostEndDelegateAuthOutput {
    std::vector<uint8_t> fwkMsg;
    AuthType authType;
    Atl atl;
};

struct HostCancelDelegateAuthInput {
    RequestId requestId;
};

struct CompanionDelegateAuthBeginInput {
    RequestId requestId;
    BindingId bindingId;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> startDelegateAuthRequest;
};

struct CompanionDelegateAuthBeginOutput {
    uint64_t challenge;
    Atl atl;
};

struct CompanionDelegateAuthEndInput {
    RequestId requestId;
    ResultCode resultCode;
    std::vector<uint8_t> authToken;
};

struct CompanionDelegateAuthEndOutput {
    std::vector<uint8_t> delegateAuthResult;
};

// Issue token input/output structs
struct HostPreIssueTokenInput {
    RequestId requestId;
    TemplateId templateId;
    std::vector<uint8_t> fwkUnlockMsg;
};

struct HostPreIssueTokenOutput {
    std::vector<uint8_t> preIssueTokenRequest;
};

struct HostBeginIssueTokenInput {
    RequestId requestId;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> preIssueTokenReply;
};

struct HostBeginIssueTokenOutput {
    std::vector<uint8_t> issueTokenRequest;
};

struct HostEndIssueTokenInput {
    RequestId requestId;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> issueTokenReply;
};

struct HostEndIssueTokenOutput {
    Atl atl;
};

struct HostCancelIssueTokenInput {
    RequestId requestId;
};

struct CompanionPreIssueTokenInput {
    RequestId requestId;
    BindingId bindingId;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> preIssueTokenRequest;
};

struct CompanionPreIssueTokenOutput {
    std::vector<uint8_t> preIssueTokenReply;
};

struct CompanionProcessIssueTokenInput {
    RequestId requestId;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> issueTokenRequest;
};

struct CompanionProcessIssueTokenOutput {
    std::vector<uint8_t> issueTokenReply;
};

struct CompanionCancelIssueTokenInput {
    RequestId requestId;
};

// Obtain token input/output structs
struct HostProcessPreObtainTokenInput {
    RequestId requestId;
    TemplateId templateId;
    SecureProtocolId secureProtocolId;
};

struct HostProcessPreObtainTokenOutput {
    std::vector<uint8_t> preObtainTokenReply;
};

struct CompanionBeginObtainTokenInput {
    RequestId requestId;
    BindingId bindingId;
    std::vector<uint8_t> fwkUnlockMsg;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> preObtainTokenReply;
};

struct CompanionBeginObtainTokenOutput {
    std::vector<uint8_t> obtainTokenRequest;
};

struct CompanionEndObtainTokenInput {
    RequestId requestId;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> obtainTokenReply;
};

struct HostProcessObtainTokenInput {
    RequestId requestId;
    TemplateId templateId;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> obtainTokenRequest;
};

struct HostProcessObtainTokenOutput {
    std::vector<uint8_t> obtainTokenReply;
    Atl atl;
};

struct HostCancelObtainTokenInput {
    RequestId requestId;
};

struct CompanionCancelObtainTokenInput {
    RequestId requestId;
};

// Token auth input/output structs
struct HostBeginTokenAuthInput {
    RequestId requestId;
    ScheduleId scheduleId;
    TemplateId templateId;
    std::vector<uint8_t> fwkMsg;
};

struct HostBeginTokenAuthOutput {
    std::vector<uint8_t> tokenAuthRequest;
};

struct HostEndTokenAuthInput {
    RequestId requestId;
    TemplateId templateId;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> tokenAuthReply;
};

struct HostEndTokenAuthOutput {
    std::vector<uint8_t> fwkMsg;
};

struct CompanionProcessTokenAuthInput {
    BindingId bindingId;
    SecureProtocolId secureProtocolId;
    std::vector<uint8_t> tokenAuthRequest;
};

struct CompanionProcessTokenAuthOutput {
    std::vector<uint8_t> tokenAuthReply;
};

// Update companion status input/output structs
struct HostUpdateCompanionStatusInput {
    TemplateId templateId;
    std::string companionDeviceName;
    std::string companionDeviceUserName;
};

struct HostUpdateCompanionEnabledBusinessIdsInput {
    TemplateId templateId;
    std::vector<BusinessIdType> enabledBusinessIds;
};

// Revoke operations input structs
struct HostRevokeTokenInput {
    TemplateId templateId;
};

struct CompanionRevokeTokenInput {
    BindingId bindingId;
};

class ISecurityAgent {
public:
    virtual ~ISecurityAgent() = default;

    // Framework interaction
    virtual ResultCode Init() = 0;
    virtual ResultCode SetActiveUser(const SetActiveUserInput &input) = 0;
    virtual ResultCode HostGetExecutorInfo(HostGetExecutorInfoOutput &output) = 0;
    virtual ResultCode HostOnRegisterFinish(const RegisterFinishInput &input) = 0;
    virtual ResultCode HostGetPersistedCompanionStatus(const HostGetPersistedCompanionStatusInput &input,
        HostGetPersistedCompanionStatusOutput &output) = 0;
    virtual ResultCode CompanionGetPersistedHostBindingStatus(const CompanionGetPersistedHostBindingStatusInput &input,
        CompanionGetPersistedHostBindingStatusOutput &output) = 0;

    // Companion check
    virtual ResultCode HostBeginCompanionCheck(const HostBeginCompanionCheckInput &input,
        HostBeginCompanionCheckOutput &output) = 0;
    virtual ResultCode HostEndCompanionCheck(const HostEndCompanionCheckInput &input) = 0;
    virtual ResultCode HostCancelCompanionCheck(const HostCancelCompanionCheckInput &input) = 0;

    virtual ResultCode CompanionProcessCheck(const CompanionProcessCheckInput &input,
        CompanionProcessCheckOutput &output) = 0;

    // Add companion device (binding)
    virtual ResultCode HostGetInitKeyNegotiationRequest(const HostGetInitKeyNegotiationRequestInput &input,
        HostGetInitKeyNegotiationRequestOutput &output) = 0;
    virtual ResultCode HostBeginAddCompanion(const HostBeginAddCompanionInput &input,
        HostBeginAddCompanionOutput &output) = 0;
    virtual ResultCode HostEndAddCompanion(const HostEndAddCompanionInput &input,
        HostEndAddCompanionOutput &output) = 0;
    virtual ResultCode HostCancelAddCompanion(const HostCancelAddCompanionInput &input) = 0;

    virtual ResultCode CompanionInitKeyNegotiation(const CompanionInitKeyNegotiationInput &input,
        CompanionInitKeyNegotiationOutput &output) = 0;
    virtual ResultCode CompanionBeginAddHostBinding(const CompanionBeginAddHostBindingInput &input,
        CompanionBeginAddHostBindingOutput &output) = 0;
    virtual ResultCode CompanionEndAddHostBinding(const CompanionEndAddHostBindingInput &input,
        CompanionEndAddHostBindingOutput &output) = 0;

    // Delete companion device (unbinding)
    virtual ResultCode HostRemoveCompanion(const HostRemoveCompanionInput &input,
        HostRemoveCompanionOutput &output) = 0;
    virtual ResultCode CompanionRemoveHostBinding(const CompanionRemoveHostBindingInput &input) = 0;

    // Delegate auth
    virtual ResultCode HostBeginDelegateAuth(const HostBeginDelegateAuthInput &input,
        HostBeginDelegateAuthOutput &output) = 0;
    virtual ResultCode HostEndDelegateAuth(const HostEndDelegateAuthInput &input,
        HostEndDelegateAuthOutput &output) = 0;
    virtual ResultCode HostCancelDelegateAuth(const HostCancelDelegateAuthInput &input) = 0;

    virtual ResultCode CompanionBeginDelegateAuth(const CompanionDelegateAuthBeginInput &input,
        CompanionDelegateAuthBeginOutput &output) = 0;
    virtual ResultCode CompanionEndDelegateAuth(const CompanionDelegateAuthEndInput &input,
        CompanionDelegateAuthEndOutput &output) = 0;

    // Issue token
    virtual ResultCode HostPreIssueToken(const HostPreIssueTokenInput &input, HostPreIssueTokenOutput &output) = 0;
    virtual ResultCode HostBeginIssueToken(const HostBeginIssueTokenInput &input,
        HostBeginIssueTokenOutput &output) = 0;
    virtual ResultCode HostEndIssueToken(const HostEndIssueTokenInput &input, HostEndIssueTokenOutput &output) = 0;
    virtual ResultCode HostCancelIssueToken(const HostCancelIssueTokenInput &input) = 0;

    virtual ResultCode CompanionPreIssueToken(const CompanionPreIssueTokenInput &input,
        CompanionPreIssueTokenOutput &output) = 0;
    virtual ResultCode CompanionProcessIssueToken(const CompanionProcessIssueTokenInput &input,
        CompanionProcessIssueTokenOutput &output) = 0;
    virtual ResultCode CompanionCancelIssueToken(const CompanionCancelIssueTokenInput &input) = 0;

    // Obtain token
    virtual ResultCode HostProcessPreObtainToken(const HostProcessPreObtainTokenInput &input,
        HostProcessPreObtainTokenOutput &output) = 0;
    virtual ResultCode HostProcessObtainToken(const HostProcessObtainTokenInput &input,
        HostProcessObtainTokenOutput &output) = 0;
    virtual ResultCode HostCancelObtainToken(const HostCancelObtainTokenInput &input) = 0;

    virtual ResultCode CompanionBeginObtainToken(const CompanionBeginObtainTokenInput &input,
        CompanionBeginObtainTokenOutput &output) = 0;
    virtual ResultCode CompanionEndObtainToken(const CompanionEndObtainTokenInput &input) = 0;
    virtual ResultCode CompanionCancelObtainToken(const CompanionCancelObtainTokenInput &input) = 0;

    // Token auth
    virtual ResultCode HostBeginTokenAuth(const HostBeginTokenAuthInput &input, HostBeginTokenAuthOutput &output) = 0;
    virtual ResultCode HostEndTokenAuth(const HostEndTokenAuthInput &input, HostEndTokenAuthOutput &output) = 0;

    virtual ResultCode CompanionProcessTokenAuth(const CompanionProcessTokenAuthInput &input,
        CompanionProcessTokenAuthOutput &output) = 0;

    // Update companion device status
    virtual ResultCode HostUpdateCompanionStatus(const HostUpdateCompanionStatusInput &input) = 0;
    virtual ResultCode HostUpdateCompanionEnabledBusinessIds(
        const HostUpdateCompanionEnabledBusinessIdsInput &input) = 0;

    // Revoke token
    virtual ResultCode HostRevokeToken(const HostRevokeTokenInput &input) = 0;
    virtual ResultCode CompanionRevokeToken(const CompanionRevokeTokenInput &input) = 0;

private:
    virtual void Initialize() = 0;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SECURITY_AGENT_H
