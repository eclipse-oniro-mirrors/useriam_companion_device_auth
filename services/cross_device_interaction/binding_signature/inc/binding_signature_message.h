/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_BINDING_SIGNATURE_MESSAGE_H
#define COMPANION_DEVICE_AUTH_BINDING_SIGNATURE_MESSAGE_H

#include <cstdint>
#include <optional>
#include <vector>

#include "cda_attributes.h"
#include "security_agent.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
constexpr size_t BINDING_SIGNATURE_CHALLENGE_LEN = 32;

struct GetBindingSignatureChallengeRequest {
    DeviceKey hostDeviceKey {};
    std::optional<UserKey> companionUserKey {};
    std::string connectionName {};
};

struct GetBindingSignatureChallengeReply {
    ResultCode result { ResultCode::GENERAL_ERROR };
    UserKey companionUserKey {};
    std::vector<uint8_t> challenge {};
};

void EncodeGetBindingSignatureChallengeRequest(const GetBindingSignatureChallengeRequest &request,
    Attributes &attributes);
std::optional<GetBindingSignatureChallengeRequest> DecodeGetBindingSignatureChallengeRequest(
    const Attributes &attributes);
void EncodeGetBindingSignatureChallengeReply(const GetBindingSignatureChallengeReply &reply, Attributes &attributes);
std::optional<GetBindingSignatureChallengeReply> DecodeGetBindingSignatureChallengeReply(const Attributes &attributes);
bool HasBindingSignatureAttributes(const Attributes &attributes);
std::optional<BindingSignatureProof> DecodeBindingSignatureAttributes(const Attributes &attributes);
void AttachBindingSignatureAttributes(const std::vector<uint8_t> &challenge, const std::vector<uint8_t> &signature,
    Attributes &attributes);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_BINDING_SIGNATURE_MESSAGE_H
