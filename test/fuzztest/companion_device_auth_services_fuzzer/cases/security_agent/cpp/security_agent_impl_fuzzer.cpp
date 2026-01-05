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

#include "command_invoker.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "security_agent_imp.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const size_t TEST_VAL1024 = 1024;
}

using FuzzFunction = void (*)(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData);

static void FuzzInit(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    agent->Init();
}

static void FuzzInitialize(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    agent->Initialize();
}

static void FuzzSetActiveUser(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    SetActiveUserInput input;
    input.userId = fuzzData.ConsumeIntegral<int32_t>();
    agent->SetActiveUser(input);
}

static void FuzzHostGetExecutorInfo(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    HostGetExecutorInfoOutput output;
    agent->HostGetExecutorInfo(output);
}

static void FuzzHostOnRegisterFinish(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    RegisterFinishInput input;
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 10);
    for (uint8_t i = 0; i < count; ++i) {
        input.templateIdList.push_back(fuzzData.ConsumeIntegral<int32_t>());
    }
    size_t leftRange = 0;
    size_t rightRange = 32;
    input.fwkPublicKey = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(leftRange, rightRange));
    input.fwkMsg = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    agent->HostOnRegisterFinish(input);
}

static void FuzzHostGetPersistedCompanionStatus(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostGetPersistedCompanionStatusInput input;
    input.userId = fuzzData.ConsumeIntegral<int32_t>();
    HostGetPersistedCompanionStatusOutput output;
    agent->HostGetPersistedCompanionStatus(input, output);
}

static void FuzzCompanionGetPersistedHostBindingStatus(std::shared_ptr<SecurityAgentImpl> &agent,
    FuzzedDataProvider &fuzzData)
{
    CompanionGetPersistedHostBindingStatusInput input;
    input.userId = fuzzData.ConsumeIntegral<int32_t>();
    CompanionGetPersistedHostBindingStatusOutput output;
    agent->CompanionGetPersistedHostBindingStatus(input, output);
}

static void FuzzHostBeginCompanionCheck(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostBeginCompanionCheckInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    HostBeginCompanionCheckOutput output;
    agent->HostBeginCompanionCheck(input, output);
}

static void FuzzHostEndCompanionCheck(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostEndCompanionCheckInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 10);
    for (uint8_t i = 0; i < count; ++i) {
        input.protocolVersionList.push_back(fuzzData.ConsumeIntegral<uint16_t>());
        input.capabilityList.push_back(fuzzData.ConsumeIntegral<uint16_t>());
    }
    input.companionCheckResponse =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    agent->HostEndCompanionCheck(input);
}

static void FuzzHostCancelCompanionCheck(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostCancelCompanionCheckInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    agent->HostCancelCompanionCheck(input);
}

static void FuzzCompanionProcessCheck(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionProcessCheckInput input;
    input.companionCheckRequest =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    CompanionProcessCheckOutput output;
    agent->CompanionProcessCheck(input, output);
}

static void FuzzHostGetInitKeyNegotiationRequest(std::shared_ptr<SecurityAgentImpl> &agent,
    FuzzedDataProvider &fuzzData)
{
    HostGetInitKeyNegotiationRequestInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    HostGetInitKeyNegotiationRequestOutput output;
    agent->HostGetInitKeyNegotiationRequest(input, output);
}

static void FuzzHostBeginAddCompanion(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostBeginAddCompanionInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    input.companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    input.fwkMsg = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    input.initKeyNegotiationReply =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    HostBeginAddCompanionOutput output;
    agent->HostBeginAddCompanion(input, output);
}

static void FuzzHostEndAddCompanion(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostEndAddCompanionInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.companionStatus.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    input.companionStatus.hostUserId = fuzzData.ConsumeIntegral<int32_t>();
    input.addHostBindingReply =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    HostEndAddCompanionOutput output;
    agent->HostEndAddCompanion(input, output);
}

static void FuzzHostCancelAddCompanion(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostCancelAddCompanionInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    agent->HostCancelAddCompanion(input);
}

static void FuzzHostActivateToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostActivateTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    agent->HostActivateToken(input);
}

static void FuzzCompanionInitKeyNegotiation(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionInitKeyNegotiationInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    input.hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    input.initKeyNegotiationRequest =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    CompanionInitKeyNegotiationOutput output;
    agent->CompanionInitKeyNegotiation(input, output);
}

static void FuzzCompanionBeginAddHostBinding(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionBeginAddHostBindingInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.addHostBindingRequest =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    CompanionBeginAddHostBindingOutput output;
    agent->CompanionBeginAddHostBinding(input, output);
}

static void FuzzCompanionEndAddHostBinding(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionEndAddHostBindingInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.resultCode = static_cast<ResultCode>(fuzzData.ConsumeIntegral<int32_t>());
    input.tokenData = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    CompanionEndAddHostBindingOutput output;
    agent->CompanionEndAddHostBinding(input, output);
}

static void FuzzHostRemoveCompanion(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostRemoveCompanionInput input;
    input.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    HostRemoveCompanionOutput output;
    agent->HostRemoveCompanion(input, output);
}

static void FuzzCompanionRemoveHostBinding(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionRemoveHostBindingInput input;
    input.bindingId = fuzzData.ConsumeIntegral<uint32_t>();
    agent->CompanionRemoveHostBinding(input);
}

static void FuzzHostBeginDelegateAuth(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostBeginDelegateAuthInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
    input.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    input.fwkMsg = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    HostBeginDelegateAuthOutput output;
    agent->HostBeginDelegateAuth(input, output);
}

static void FuzzHostEndDelegateAuth(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostEndDelegateAuthInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.delegateAuthResult = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    HostEndDelegateAuthOutput output;
    agent->HostEndDelegateAuth(input, output);
}

static void FuzzHostCancelDelegateAuth(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostCancelDelegateAuthInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    agent->HostCancelDelegateAuth(input);
}

static void FuzzCompanionBeginDelegateAuth(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionDelegateAuthBeginInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.bindingId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.startDelegateAuthRequest =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    CompanionDelegateAuthBeginOutput output;
    agent->CompanionBeginDelegateAuth(input, output);
}

static void FuzzCompanionEndDelegateAuth(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionDelegateAuthEndInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.resultCode = static_cast<ResultCode>(fuzzData.ConsumeIntegral<int32_t>());
    input.authToken = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    CompanionDelegateAuthEndOutput output;
    agent->CompanionEndDelegateAuth(input, output);
}

static void FuzzHostPreIssueToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostPreIssueTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    input.fwkUnlockMsg = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    HostPreIssueTokenOutput output;
    agent->HostPreIssueToken(input, output);
}

static void FuzzHostBeginIssueToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostBeginIssueTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.preIssueTokenReply = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    HostBeginIssueTokenOutput output;
    agent->HostBeginIssueToken(input, output);
}

static void FuzzHostEndIssueToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostEndIssueTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.issueTokenReply = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    HostEndIssueTokenOutput output;
    agent->HostEndIssueToken(input, output);
}

static void FuzzHostCancelIssueToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostCancelIssueTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    agent->HostCancelIssueToken(input);
}

static void FuzzCompanionPreIssueToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionPreIssueTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.bindingId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.preIssueTokenRequest =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    CompanionPreIssueTokenOutput output;
    agent->CompanionPreIssueToken(input, output);
}

static void FuzzCompanionProcessIssueToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionProcessIssueTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.issueTokenRequest = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    CompanionProcessIssueTokenOutput output;
    agent->CompanionProcessIssueToken(input, output);
}

static void FuzzCompanionCancelIssueToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionCancelIssueTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    agent->CompanionCancelIssueToken(input);
}

static void FuzzHostProcessPreObtainToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostProcessPreObtainTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    HostProcessPreObtainTokenOutput output;
    agent->HostProcessPreObtainToken(input, output);
}

static void FuzzHostProcessObtainToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostProcessObtainTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.obtainTokenRequest = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    HostProcessObtainTokenOutput output;
    agent->HostProcessObtainToken(input, output);
}

static void FuzzHostCancelObtainToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostCancelObtainTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    agent->HostCancelObtainToken(input);
}

static void FuzzCompanionBeginObtainToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionBeginObtainTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.bindingId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.fwkUnlockMsg = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    input.preObtainTokenReply =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    CompanionBeginObtainTokenOutput output;
    agent->CompanionBeginObtainToken(input, output);
}

static void FuzzCompanionEndObtainToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionEndObtainTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.obtainTokenReply = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    agent->CompanionEndObtainToken(input);
}

static void FuzzCompanionCancelObtainToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionCancelObtainTokenInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    agent->CompanionCancelObtainToken(input);
}

static void FuzzHostBeginTokenAuth(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostBeginTokenAuthInput input;
    input.scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
    input.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    input.fwkMsg = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    HostBeginTokenAuthOutput output;
    agent->HostBeginTokenAuth(input, output);
}

static void FuzzHostEndTokenAuth(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostEndTokenAuthInput input;
    input.requestId = fuzzData.ConsumeIntegral<uint32_t>();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    input.tokenAuthReply = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    HostEndTokenAuthOutput output;
    agent->HostEndTokenAuth(input, output);
}

static void FuzzCompanionProcessTokenAuth(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionProcessTokenAuthInput input;
    input.tokenAuthRequest = fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, TEST_VAL1024));
    CompanionProcessTokenAuthOutput output;
    agent->CompanionProcessTokenAuth(input, output);
}

static void FuzzHostRevokeToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostRevokeTokenInput input;
    input.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    agent->HostRevokeToken(input);
}

static void FuzzCompanionRevokeToken(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    CompanionRevokeTokenInput input;
    input.bindingId = fuzzData.ConsumeIntegral<uint32_t>();
    agent->CompanionRevokeToken(input);
}

static void FuzzHostUpdateCompanionStatus(std::shared_ptr<SecurityAgentImpl> &agent, FuzzedDataProvider &fuzzData)
{
    HostUpdateCompanionStatusInput input;
    input.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    uint32_t testVal64 = 64;
    input.companionDeviceName = GenerateFuzzString(fuzzData, testVal64);
    input.companionDeviceUserName = GenerateFuzzString(fuzzData, testVal64);
    agent->HostUpdateCompanionStatus(input);
}

static void FuzzHostUpdateCompanionEnabledBusinessIds(std::shared_ptr<SecurityAgentImpl> &agent,
    FuzzedDataProvider &fuzzData)
{
    HostUpdateCompanionEnabledBusinessIdsInput input;
    input.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 10);
    for (uint8_t i = 0; i < count; ++i) {
        input.enabledBusinessIds.push_back(fuzzData.ConsumeIntegral<uint32_t>());
    }
    agent->HostUpdateCompanionEnabledBusinessIds(input);
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzInit,
    FuzzInitialize,
    FuzzSetActiveUser,
    FuzzHostGetExecutorInfo,
    FuzzHostOnRegisterFinish,
    FuzzHostGetPersistedCompanionStatus,
    FuzzCompanionGetPersistedHostBindingStatus,
    FuzzHostBeginCompanionCheck,
    FuzzHostEndCompanionCheck,
    FuzzHostCancelCompanionCheck,
    FuzzCompanionProcessCheck,
    FuzzHostGetInitKeyNegotiationRequest,
    FuzzHostBeginAddCompanion,
    FuzzHostEndAddCompanion,
    FuzzHostCancelAddCompanion,
    FuzzHostActivateToken,
    FuzzCompanionInitKeyNegotiation,
    FuzzCompanionBeginAddHostBinding,
    FuzzCompanionEndAddHostBinding,
    FuzzHostRemoveCompanion,
    FuzzCompanionRemoveHostBinding,
    FuzzHostBeginDelegateAuth,
    FuzzHostEndDelegateAuth,
    FuzzHostCancelDelegateAuth,
    FuzzCompanionBeginDelegateAuth,
    FuzzCompanionEndDelegateAuth,
    FuzzHostPreIssueToken,
    FuzzHostBeginIssueToken,
    FuzzHostEndIssueToken,
    FuzzHostCancelIssueToken,
    FuzzCompanionPreIssueToken,
    FuzzCompanionProcessIssueToken,
    FuzzCompanionCancelIssueToken,
    FuzzHostProcessPreObtainToken,
    FuzzHostProcessObtainToken,
    FuzzHostCancelObtainToken,
    FuzzCompanionBeginObtainToken,
    FuzzCompanionEndObtainToken,
    FuzzCompanionCancelObtainToken,
    FuzzHostBeginTokenAuth,
    FuzzHostEndTokenAuth,
    FuzzCompanionProcessTokenAuth,
    FuzzHostRevokeToken,
    FuzzCompanionRevokeToken,
    FuzzHostUpdateCompanionStatus,
    FuzzHostUpdateCompanionEnabledBusinessIds,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzSecurityAgentImpl(FuzzedDataProvider &fuzzData)
{
    auto invoker = std::make_shared<CommandInvoker>();
    auto agent = std::make_shared<SecurityAgentImpl>(invoker);
    if (!agent) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](agent, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
