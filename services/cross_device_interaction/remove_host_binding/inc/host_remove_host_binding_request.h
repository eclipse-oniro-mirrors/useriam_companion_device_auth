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

#ifndef COMPANION_DEVICE_AUTH_REMOVE_HOST_BINDING_REQUEST_H
#define COMPANION_DEVICE_AUTH_REMOVE_HOST_BINDING_REQUEST_H

#include <memory>

#include "outbound_request.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class HostRemoveHostBindingRequest : public std::enable_shared_from_this<HostRemoveHostBindingRequest>,
                                     public OutboundRequest {
public:
    HostRemoveHostBindingRequest(UserId hostUserId, TemplateId templateId, const DeviceKey &companionDeviceKey);
    ~HostRemoveHostBindingRequest() override = default;

    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const override;

protected:
    bool OnStart(ErrorGuard &errorGuard) override;
    void OnConnected() override;
    std::weak_ptr<OutboundRequest> GetWeakPtr() override;

    void CompleteWithError(ResultCode result) override;

private:
    void SendRemoveHostBindingRequest();
    void HandleRemoveHostBindingReply(const Attributes &message);
    void CompleteWithSuccess();

    UserId hostUserId_ = INVALID_USER_ID;
    DeviceKey companionDeviceKey_;
    TemplateId templateId_ = 0;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_REMOVE_HOST_BINDING_REQUEST_H
