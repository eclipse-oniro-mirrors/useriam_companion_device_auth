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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_GET_BINDING_SIGNATURE_CHALLENGE_HANDLER_H
#define COMPANION_DEVICE_AUTH_COMPANION_GET_BINDING_SIGNATURE_CHALLENGE_HANDLER_H

#include <cstdint>
#include <string>
#include <vector>

#include "binding_signature_message.h"
#include "sync_incoming_message_handler.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionGetBindingSignatureChallengeHandler : public SyncIncomingMessageHandler {
public:
    CompanionGetBindingSignatureChallengeHandler();

protected:
    void HandleRequest(const Attributes &request, Attributes &reply) override;

private:
    struct ConnectionEntry {
        std::string connectionName;
        std::vector<uint8_t> challenge;
        std::unique_ptr<Subscription> statusSubscription;
    };

    ResultCode IssueChallenge(const std::string &connectionName,
        CompanionGenerateBindingSignatureChallengeOutput &output);
    ResultCode ResolveChallengeIdentity(const GetBindingSignatureChallengeRequest &challengeRequest,
        UserKey &companionUserKey);
    void HandleConnectionStatus(const std::string &connName, ConnectionStatus status, const std::string &reason);
    void PurgeChallenge(const std::vector<uint8_t> &challenge);

    std::vector<ConnectionEntry> connections_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_GET_BINDING_SIGNATURE_CHALLENGE_HANDLER_H
