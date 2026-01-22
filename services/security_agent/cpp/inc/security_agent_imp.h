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

#ifndef COMPANION_DEVICE_AUTH_SECURITY_AGENT_IMPL_H
#define COMPANION_DEVICE_AUTH_SECURITY_AGENT_IMPL_H

#include <cstdint>
#include <memory>
#include <string>

#include "nocopyable.h"
#include "securec.h"

#include "iam_logger.h"

#include "common_defines.h"
#include "security_agent.h"
#include "security_command_adapter.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class SecurityAgentImpl : public ISecurityAgent {
public:
    static std::shared_ptr<ISecurityAgent> Create();
    ~SecurityAgentImpl() override = default;

    // Framework interaction
    ResultCode Init() override;
    ResultCode SetActiveUser(const SetActiveUserInput &input) override;
    ResultCode HostGetExecutorInfo(HostGetExecutorInfoOutput &output) override;
    ResultCode HostOnRegisterFinish(const RegisterFinishInput &input) override;
    ResultCode HostGetPersistedCompanionStatus(const HostGetPersistedCompanionStatusInput &input,
        HostGetPersistedCompanionStatusOutput &output) override;
    ResultCode CompanionGetPersistedHostBindingStatus(const CompanionGetPersistedHostBindingStatusInput &input,
        CompanionGetPersistedHostBindingStatusOutput &output) override;

    // Companion check
    ResultCode HostBeginCompanionCheck(const HostBeginCompanionCheckInput &input,
        HostBeginCompanionCheckOutput &output) override;
    ResultCode HostEndCompanionCheck(const HostEndCompanionCheckInput &input) override;
    ResultCode HostCancelCompanionCheck(const HostCancelCompanionCheckInput &input) override;

    ResultCode CompanionProcessCheck(const CompanionProcessCheckInput &input,
        CompanionProcessCheckOutput &output) override;

    // Add companion device (binding)
    ResultCode HostGetInitKeyNegotiationRequest(const HostGetInitKeyNegotiationRequestInput &input,
        HostGetInitKeyNegotiationRequestOutput &output) override;
    ResultCode HostBeginAddCompanion(const HostBeginAddCompanionInput &input,
        HostBeginAddCompanionOutput &output) override;
    ResultCode HostEndAddCompanion(const HostEndAddCompanionInput &input, HostEndAddCompanionOutput &output) override;
    ResultCode HostCancelAddCompanion(const HostCancelAddCompanionInput &input) override;

    ResultCode CompanionInitKeyNegotiation(const CompanionInitKeyNegotiationInput &input,
        CompanionInitKeyNegotiationOutput &output) override;
    ResultCode CompanionBeginAddHostBinding(const CompanionBeginAddHostBindingInput &input,
        CompanionBeginAddHostBindingOutput &output) override;
    ResultCode CompanionEndAddHostBinding(const CompanionEndAddHostBindingInput &input,
        CompanionEndAddHostBindingOutput &output) override;

    // Delete companion device (unbinding)
    ResultCode HostRemoveCompanion(const HostRemoveCompanionInput &input, HostRemoveCompanionOutput &output) override;
    ResultCode CompanionRemoveHostBinding(const CompanionRemoveHostBindingInput &input) override;

    // Delegate auth
    ResultCode HostBeginDelegateAuth(const HostBeginDelegateAuthInput &input,
        HostBeginDelegateAuthOutput &output) override;
    ResultCode HostEndDelegateAuth(const HostEndDelegateAuthInput &input, HostEndDelegateAuthOutput &output) override;
    ResultCode HostCancelDelegateAuth(const HostCancelDelegateAuthInput &input) override;

    ResultCode CompanionBeginDelegateAuth(const CompanionDelegateAuthBeginInput &input,
        CompanionDelegateAuthBeginOutput &output) override;
    ResultCode CompanionEndDelegateAuth(const CompanionDelegateAuthEndInput &input,
        CompanionDelegateAuthEndOutput &output) override;

    // Issue token
    ResultCode HostPreIssueToken(const HostPreIssueTokenInput &input, HostPreIssueTokenOutput &output) override;
    ResultCode HostBeginIssueToken(const HostBeginIssueTokenInput &input, HostBeginIssueTokenOutput &output) override;
    ResultCode HostEndIssueToken(const HostEndIssueTokenInput &input, HostEndIssueTokenOutput &output) override;
    ResultCode HostCancelIssueToken(const HostCancelIssueTokenInput &input) override;

    ResultCode CompanionPreIssueToken(const CompanionPreIssueTokenInput &input,
        CompanionPreIssueTokenOutput &output) override;
    ResultCode CompanionProcessIssueToken(const CompanionProcessIssueTokenInput &input,
        CompanionProcessIssueTokenOutput &output) override;
    ResultCode CompanionCancelIssueToken(const CompanionCancelIssueTokenInput &input) override;

    // Obtain token
    ResultCode HostProcessPreObtainToken(const HostProcessPreObtainTokenInput &input,
        HostProcessPreObtainTokenOutput &output) override;
    ResultCode HostProcessObtainToken(const HostProcessObtainTokenInput &input,
        HostProcessObtainTokenOutput &output) override;
    ResultCode HostCancelObtainToken(const HostCancelObtainTokenInput &input) override;

    ResultCode CompanionBeginObtainToken(const CompanionBeginObtainTokenInput &input,
        CompanionBeginObtainTokenOutput &output) override;
    ResultCode CompanionEndObtainToken(const CompanionEndObtainTokenInput &input) override;
    ResultCode CompanionCancelObtainToken(const CompanionCancelObtainTokenInput &input) override;

    // Token auth
    ResultCode HostBeginTokenAuth(const HostBeginTokenAuthInput &input, HostBeginTokenAuthOutput &output) override;
    ResultCode HostEndTokenAuth(const HostEndTokenAuthInput &input, HostEndTokenAuthOutput &output) override;
    ResultCode HostUpdateToken(const HostUpdateTokenInput &input, HostUpdateTokenOutput &output) override;

    ResultCode CompanionProcessTokenAuth(const CompanionProcessTokenAuthInput &input,
        CompanionProcessTokenAuthOutput &output) override;

    // Revoke token
    ResultCode HostRevokeToken(const HostRevokeTokenInput &input) override;
    ResultCode CompanionRevokeToken(const CompanionRevokeTokenInput &input) override;

    // Update companion device status
    ResultCode HostUpdateCompanionStatus(const HostUpdateCompanionStatusInput &input) override;
    ResultCode HostUpdateCompanionEnabledBusinessIds(const HostUpdateCompanionEnabledBusinessIdsInput &input) override;
    ResultCode HostCheckTemplateEnrolled(const HostCheckTemplateEnrolledInput &input,
        HostCheckTemplateEnrolledOutput &output) override;

private:
    SecurityAgentImpl();
    void Initialize() override;
    std::unique_ptr<Subscription> activeUserSubscription_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SECURITY_AGENT_IMPL_H
