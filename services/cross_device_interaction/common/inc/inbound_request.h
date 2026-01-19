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

#ifndef COMPANION_DEVICE_AUTH_INBOUND_REQUEST_H
#define COMPANION_DEVICE_AUTH_INBOUND_REQUEST_H

#include <memory>
#include <string>
#include <vector>

#include "base_request.h"
#include "cda_attributes.h"
#include "cross_device_comm_manager.h"
#include "error_guard.h"
#include "request_manager.h"
#include "service_common.h"
#include "subscription.h"
#include "task_runner_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class InboundRequest : public BaseRequest {
public:
    InboundRequest(RequestType requestType, const std::string &connectionName, const DeviceKey &peerDeviceKey);
    virtual ~InboundRequest() = default;

    void Start() override final;
    bool Cancel(ResultCode resultCode) override final;

protected:
    virtual bool OnStart(ErrorGuard &errorGuard) = 0;

    virtual std::weak_ptr<InboundRequest> GetWeakPtr() = 0;

    std::optional<DeviceKey> GetPeerDeviceKey() const override;
    const DeviceKey &PeerDeviceKey() const;
    const std::string &GetConnectionName() const;

    void SendRequestAborted(ResultCode result, const std::string &reason);
    void CompleteWithError(ResultCode result) override;

private:
    void HandleConnectionStatus(const std::string &connName, ConnectionStatus status, const std::string &reason);

    std::string connectionName_;
    std::unique_ptr<Subscription> connectionStatusSubscription_;
    std::optional<DeviceKey> peerDeviceKey_ {};
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_INBOUND_REQUEST_H
