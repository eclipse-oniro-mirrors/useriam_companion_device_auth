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

#ifndef COMPANION_DEVICE_AUTH_HOST_SYNC_DEVICE_STATUS_REQUEST_H
#define COMPANION_DEVICE_AUTH_HOST_SYNC_DEVICE_STATUS_REQUEST_H

#include <functional>
#include <memory>

#include "companion_manager.h"
#include "outbound_request.h"
#include "scope_guard.h"
#include "security_agent.h"
#include "sync_device_status_message.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SyncDeviceStatusCallback = std::function<void(ResultCode result, const SyncDeviceStatus &syncDeviceStatus)>;

class HostSyncDeviceStatusRequest : public std::enable_shared_from_this<HostSyncDeviceStatusRequest>,
                                    public OutboundRequest {
public:
    HostSyncDeviceStatusRequest(int32_t hostUserId, const DeviceKey &companionDeviceKey,
        const std::string &companionDeviceName, SyncDeviceStatusCallback &&callback);
    ~HostSyncDeviceStatusRequest() override = default;

    // Implement preemption interfaces
    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const override;

protected:
    void OnConnected() override;
    std::weak_ptr<OutboundRequest> GetWeakPtr() override;
    void CompleteWithError(ResultCode result) override;

private:
    void CompleteWithSuccess(const SyncDeviceStatus &syncDeviceStatus);

    void BeginCompanionCheck();
    bool SendSyncDeviceStatusRequest(const std::vector<uint8_t> &salt, uint64_t challenge);
    void HandleSyncDeviceStatusReply(const Attributes &reply);
    bool EndCompanionCheck(const SyncDeviceStatusReply &reply);
    bool NeedBeginCompanionCheck() const;

    int32_t hostUserId_ = INVALID_USER_ID;
    std::unique_ptr<ScopeGuard> cancelCompanionCheckGuard_;
    DeviceKey companionDeviceKey_;
    std::string companionDeviceName_;
    SyncDeviceStatusCallback callback_;

    void InvokeCallback(ResultCode result, const SyncDeviceStatus &syncDeviceStatus);
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_SYNC_DEVICE_STATUS_REQUEST_H
