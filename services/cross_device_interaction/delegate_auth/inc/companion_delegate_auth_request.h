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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_DELEGATE_AUTH_REQUEST_H
#define COMPANION_DEVICE_AUTH_COMPANION_DELEGATE_AUTH_REQUEST_H

#include <memory>
#include <optional>

#include "host_binding_manager.h"
#include "inbound_request.h"
#include "request_callback.h"
#include "security_agent.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionDelegateAuthRequest : public InboundRequest,
                                     public std::enable_shared_from_this<CompanionDelegateAuthRequest> {
public:
    CompanionDelegateAuthRequest(const std::string &connectionName, int32_t companionUserId,
        const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &startDelegateAuthRequest);
    ~CompanionDelegateAuthRequest() override;

    bool CompanionBeginDelegateAuth();

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
    bool SecureAgentBeginDelegateAuth(uint64_t &challenge, Atl &atl);
    bool SecurityAgentEndDelegateAuth(ResultCode resultCode, const std::vector<uint8_t> &authToken,
        std::vector<uint8_t> &extraInfo);
    void HandleDelegateAuthResult(ResultCode resultCode, const std::vector<uint8_t> &extraInfo);
    bool SendDelegateAuthResult(ResultCode resultCode, const std::vector<uint8_t> &delegateAuthResult);
    void HandleSendDelegateAuthResultReply(const Attributes &message);

    int32_t companionUserId_ = 0;
    std::vector<uint8_t> startDelegateAuthRequest_;
    bool authResultSent_ = false;
    std::optional<uint64_t> contextId_ = std::nullopt;
    DeviceKey hostDeviceKey_ {};
    SecureProtocolId secureProtocolId_ { SecureProtocolId::INVALID };
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_DELEGATE_AUTH_REQUEST_H
