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

#ifndef COMPANION_DEVICE_AUTH_HOST_BINDING_SIGNATURE_CHALLENGE_REQUESTER_H
#define COMPANION_DEVICE_AUTH_HOST_BINDING_SIGNATURE_CHALLENGE_REQUESTER_H

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

struct BindingSignatureChallengeResult {
    UserKey companionUserKey {};
    std::vector<uint8_t> challenge {};
};

using BindingSignatureChallengeCallback =
    std::function<void(ResultCode resultCode, const BindingSignatureChallengeResult &challengeResult)>;
void RequestBindingSignatureChallenge(const std::string &connectionName, const UserKey &hostUserKey,
    const std::optional<UserKey> &companionUserKey, BindingSignatureChallengeCallback &&onResolved);
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_BINDING_SIGNATURE_CHALLENGE_REQUESTER_H
