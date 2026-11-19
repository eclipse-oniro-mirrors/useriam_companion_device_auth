/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_HOST_BINDING_PROOF_OBTAINER_H
#define COMPANION_DEVICE_AUTH_HOST_BINDING_PROOF_OBTAINER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "cda_attributes.h"
#include "host_binding_signature_challenge_requester.h"
#include "security_agent.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using BindingProofReadyCallback = std::function<void(ResultCode result)>;

class HostBindingProofObtainer : public std::enable_shared_from_this<HostBindingProofObtainer> {
public:
    static bool NeedBindingSignature(MessageType msgType, std::optional<TemplateId> templateId);

    bool HasProof() const;
    bool AttachProof(Attributes &request) const;

    void ObtainAndAttach(const std::string &connectionName, TemplateId templateId, MessageType msgType,
        const std::shared_ptr<Attributes> &request, BindingProofReadyCallback &&onBindingProofReady);

private:
    void HandleChallengeResolved(TemplateId templateId, const std::shared_ptr<Attributes> &request,
        ResultCode resultCode, const BindingSignatureChallengeResult &challengeResult,
        const BindingProofReadyCallback &onBindingProofReady);

    std::optional<BindingSignatureProof> bindingProof_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_BINDING_PROOF_OBTAINER_H
