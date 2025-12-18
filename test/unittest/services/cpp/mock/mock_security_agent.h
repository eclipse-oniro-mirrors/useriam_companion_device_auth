/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_SECURITY_AGENT_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_SECURITY_AGENT_H

#include <gmock/gmock.h>

#include "security_agent.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockSecurityAgent : public ISecurityAgent {
public:
    MOCK_METHOD(ResultCode, Init, (), (override));
    MOCK_METHOD(ResultCode, SetActiveUser, (const SetActiveUserInput &input), (override));
    MOCK_METHOD(ResultCode, HostGetExecutorInfo, (HostGetExecutorInfoOutput & output), (override));
    MOCK_METHOD(ResultCode, HostOnRegisterFinish, (const RegisterFinishInput &input), (override));
    MOCK_METHOD(ResultCode, HostGetPersistedCompanionStatus,
        (const HostGetPersistedCompanionStatusInput &input, HostGetPersistedCompanionStatusOutput &output), (override));
    MOCK_METHOD(ResultCode, CompanionGetPersistedHostBindingStatus,
        (const CompanionGetPersistedHostBindingStatusInput &input,
            CompanionGetPersistedHostBindingStatusOutput &output),
        (override));

    MOCK_METHOD(ResultCode, HostBeginCompanionCheck,
        (const HostBeginCompanionCheckInput &input, HostBeginCompanionCheckOutput &output), (override));
    MOCK_METHOD(ResultCode, HostEndCompanionCheck, (const HostEndCompanionCheckInput &input), (override));
    MOCK_METHOD(ResultCode, HostCancelCompanionCheck, (const HostCancelCompanionCheckInput &input), (override));
    MOCK_METHOD(ResultCode, CompanionProcessCheck,
        (const CompanionProcessCheckInput &input, CompanionProcessCheckOutput &output), (override));

    MOCK_METHOD(ResultCode, HostGetInitKeyNegotiationRequest,
        (const HostGetInitKeyNegotiationRequestInput &input, HostGetInitKeyNegotiationRequestOutput &output),
        (override));
    MOCK_METHOD(ResultCode, HostBeginAddCompanion,
        (const HostBeginAddCompanionInput &input, HostBeginAddCompanionOutput &output), (override));
    MOCK_METHOD(ResultCode, HostEndAddCompanion,
        (const HostEndAddCompanionInput &input, HostEndAddCompanionOutput &output), (override));
    MOCK_METHOD(ResultCode, HostCancelAddCompanion, (const HostCancelAddCompanionInput &input), (override));

    MOCK_METHOD(ResultCode, CompanionInitKeyNegotiation,
        (const CompanionInitKeyNegotiationInput &input, CompanionInitKeyNegotiationOutput &output), (override));
    MOCK_METHOD(ResultCode, CompanionBeginAddHostBinding,
        (const CompanionBeginAddHostBindingInput &input, CompanionBeginAddHostBindingOutput &output), (override));
    MOCK_METHOD(ResultCode, CompanionEndAddHostBinding,
        (const CompanionEndAddHostBindingInput &input, CompanionEndAddHostBindingOutput &output), (override));

    MOCK_METHOD(ResultCode, HostRemoveCompanion,
        (const HostRemoveCompanionInput &input, HostRemoveCompanionOutput &output), (override));
    MOCK_METHOD(ResultCode, CompanionRemoveHostBinding, (const CompanionRemoveHostBindingInput &input), (override));

    MOCK_METHOD(ResultCode, HostBeginDelegateAuth,
        (const HostBeginDelegateAuthInput &input, HostBeginDelegateAuthOutput &output), (override));
    MOCK_METHOD(ResultCode, HostEndDelegateAuth,
        (const HostEndDelegateAuthInput &input, HostEndDelegateAuthOutput &output), (override));
    MOCK_METHOD(ResultCode, HostCancelDelegateAuth, (const HostCancelDelegateAuthInput &input), (override));
    MOCK_METHOD(ResultCode, CompanionBeginDelegateAuth,
        (const CompanionDelegateAuthBeginInput &input, CompanionDelegateAuthBeginOutput &output), (override));
    MOCK_METHOD(ResultCode, CompanionEndDelegateAuth,
        (const CompanionDelegateAuthEndInput &input, CompanionDelegateAuthEndOutput &output), (override));

    MOCK_METHOD(ResultCode, HostPreIssueToken, (const HostPreIssueTokenInput &input, HostPreIssueTokenOutput &output),
        (override));
    MOCK_METHOD(ResultCode, HostBeginIssueToken,
        (const HostBeginIssueTokenInput &input, HostBeginIssueTokenOutput &output), (override));
    MOCK_METHOD(ResultCode, HostEndIssueToken, (const HostEndIssueTokenInput &input, HostEndIssueTokenOutput &output),
        (override));
    MOCK_METHOD(ResultCode, HostCancelIssueToken, (const HostCancelIssueTokenInput &input), (override));

    MOCK_METHOD(ResultCode, CompanionPreIssueToken,
        (const CompanionPreIssueTokenInput &input, CompanionPreIssueTokenOutput &output), (override));
    MOCK_METHOD(ResultCode, CompanionProcessIssueToken,
        (const CompanionProcessIssueTokenInput &input, CompanionProcessIssueTokenOutput &output), (override));
    MOCK_METHOD(ResultCode, CompanionCancelIssueToken, (const CompanionCancelIssueTokenInput &input), (override));

    MOCK_METHOD(ResultCode, HostProcessPreObtainToken,
        (const HostProcessPreObtainTokenInput &input, HostProcessPreObtainTokenOutput &output), (override));
    MOCK_METHOD(ResultCode, HostProcessObtainToken,
        (const HostProcessObtainTokenInput &input, HostProcessObtainTokenOutput &output), (override));
    MOCK_METHOD(ResultCode, HostCancelObtainToken, (const HostCancelObtainTokenInput &input), (override));
    MOCK_METHOD(ResultCode, CompanionBeginObtainToken,
        (const CompanionBeginObtainTokenInput &input, CompanionBeginObtainTokenOutput &output), (override));
    MOCK_METHOD(ResultCode, CompanionEndObtainToken, (const CompanionEndObtainTokenInput &input), (override));
    MOCK_METHOD(ResultCode, CompanionCancelObtainToken, (const CompanionCancelObtainTokenInput &input), (override));

    MOCK_METHOD(ResultCode, HostBeginTokenAuth,
        (const HostBeginTokenAuthInput &input, HostBeginTokenAuthOutput &output), (override));
    MOCK_METHOD(ResultCode, HostEndTokenAuth, (const HostEndTokenAuthInput &input, HostEndTokenAuthOutput &output),
        (override));

    MOCK_METHOD(ResultCode, CompanionProcessTokenAuth,
        (const CompanionProcessTokenAuthInput &input, CompanionProcessTokenAuthOutput &output), (override));

    MOCK_METHOD(ResultCode, HostRevokeToken, (const HostRevokeTokenInput &input), (override));
    MOCK_METHOD(ResultCode, CompanionRevokeToken, (const CompanionRevokeTokenInput &input), (override));

    MOCK_METHOD(ResultCode, HostUpdateCompanionStatus, (const HostUpdateCompanionStatusInput &input), (override));
    MOCK_METHOD(ResultCode, HostUpdateCompanionEnabledBusinessIds,
        (const HostUpdateCompanionEnabledBusinessIdsInput &input), (override));
    MOCK_METHOD(void, Initialize, (), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_SECURITY_AGENT_H
