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

#include "cda_scope_guard.h"
#include "companion_manager.h"
#include "outbound_request.h"
#include "security_agent.h"
#include "sync_device_status_message.h"
#include "user_key_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SyncDeviceStatusCallback = std::function<void(ResultCode result, const SyncDeviceStatus &syncDeviceStatus)>;

class HostSyncDeviceStatusRequest : public std::enable_shared_from_this<HostSyncDeviceStatusRequest>,
                                    public OutboundRequest {
public:
    HostSyncDeviceStatusRequest(const UserKey &hostUserKey, const DeviceKey &companionDeviceKey,
        ConnectionMode connectionMode, SyncTriggerReason triggerReason, SyncDeviceStatusCallback &&callback);
    ~HostSyncDeviceStatusRequest() override = default;

    // Implement preemption interfaces
    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(const IRequest &newRequest, uint32_t subsequentSameTypeCount) const override;

protected:
    void OnConnected() override;
    std::weak_ptr<OutboundRequest> GetWeakPtr() override;
    void CompleteWithError(ResultCode result) override;

private:
    void CompleteWithSuccess(const SyncDeviceStatus &syncDeviceStatus);

    void BeginCompanionCheck();
    bool SendSyncDeviceStatusRequest(const std::vector<uint8_t> &salt, uint64_t challenge);
    void HandleSyncDeviceStatusReply(const Attributes &reply);
    void EndCompanionCheck(const SyncDeviceStatusReply &reply, const std::optional<CompanionStatus> &companionStatus,
        std::vector<Capability> &outCapabilities);
    std::optional<CompanionStatus> QueryCompanionStatus(const SyncDeviceStatusReply &reply) const;
    ResultCode HostEndCompanionCheck(TemplateId templateId, const SyncDeviceStatusReply &reply,
        HostEndCompanionCheckOutput &output);
    SyncDeviceStatusRequest BuildSyncDeviceStatusRequest(const LocalDeviceProfile &localProfile,
        const std::vector<uint8_t> &salt, uint64_t challenge);
    ResultCode ValidateReplyParameters(const SyncDeviceStatusReply &reply) const;
    HostEndCompanionCheckInput BuildHostEndCompanionCheckInput(TemplateId templateId,
        const SyncDeviceStatusReply &reply) const;
    void CollectSyncDeviceStatusEventInfo(const LocalDeviceProfile &localProfile);
    void UpdateCompanionUserIdAndSubProfileId(const UserKey &companionUserKey);

    UserKey hostUserKey_;
    std::unique_ptr<ScopeGuard> cancelCompanionCheckGuard_;
    DeviceKey companionDeviceKey_;
    SyncDeviceStatusCallback callback_;
    std::vector<ProtocolId> hostProtocolIdList_;

    void InvokeCallback(ResultCode result, const SyncDeviceStatus &syncDeviceStatus);
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_SYNC_DEVICE_STATUS_REQUEST_H
