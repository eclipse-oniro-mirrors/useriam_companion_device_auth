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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_ADD_COMPANION_REQUEST_H
#define COMPANION_DEVICE_AUTH_COMPANION_ADD_COMPANION_REQUEST_H

#include <memory>
#include <optional>

#include "add_companion_message.h"
#include "host_binding_manager.h"
#include "inbound_request.h"
#include "security_agent.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionAddCompanionRequest : public InboundRequest,
                                     public std::enable_shared_from_this<CompanionAddCompanionRequest> {
public:
    CompanionAddCompanionRequest(const std::string &connectionName, const Attributes &request,
        OnMessageReply firstReply, const DeviceKey &hostDeviceKey);
    ~CompanionAddCompanionRequest() override = default;

    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const override;

#ifndef ENABLE_TEST
protected:
#endif
    bool OnStart(ErrorGuard &errorGuard) override;
    std::weak_ptr<InboundRequest> GetWeakPtr() override;
    void CompleteWithError(ResultCode result) override;
    void CompleteWithSuccess();

#ifndef ENABLE_TEST
private:
#endif
    bool CompanionInitKeyNegotiation(const InitKeyNegotiationRequest &request,
        std::vector<uint8_t> &initKeyNegotiationReply);
    bool SendInitKeyNegotiationReply(ResultCode result, const std::vector<uint8_t> &initKeyNegotiationReply);
    void SendErrorReply(ResultCode result);

    void HandleBeginAddCompanion(const Attributes &attrInput, OnMessageReply &onMessageReply);
    void HandleEndAddCompanion(const Attributes &attrInput, OnMessageReply &onMessageReply);

    Attributes initKeyNegoRequest_ {};
    OnMessageReply currentReply_ {};
    SecureProtocolId secureProtocolId_ { SecureProtocolId::INVALID };
    bool needCancelAddCompanion_ = false;
    std::unique_ptr<Subscription> beginAddHostBindingSubscription_;
    std::unique_ptr<Subscription> endAddHostBindingSubscription_;
    DeviceKey companionDeviceKey_ {};
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_ADD_COMPANION_REQUEST_H
