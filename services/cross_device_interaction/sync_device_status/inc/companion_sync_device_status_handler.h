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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_SYNC_DEVICE_STATUS_HANDLER_H
#define COMPANION_DEVICE_AUTH_COMPANION_SYNC_DEVICE_STATUS_HANDLER_H

#include "binding_signature_message.h"
#include "error_guard.h"
#include "host_binding_manager.h"
#include "interaction_desc.h"
#include "interaction_event_collector.h"
#include "security_agent.h"
#include "sync_device_status_message.h"
#include "sync_incoming_message_handler.h"
#include "user_key_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class CompanionSyncDeviceStatusHandler : public SyncIncomingMessageHandler {
public:
    CompanionSyncDeviceStatusHandler();
    ~CompanionSyncDeviceStatusHandler() override = default;

protected:
    void HandleRequest(const Attributes &request, Attributes &reply) override;

private:
    ResultCode NegotiateSyncParameters(const SyncDeviceStatusRequest &syncRequest,
        const LocalDeviceProfile &localProfile, const std::optional<HostBindingStatus> &proofBindingStatus,
        ErrorGuard &errorGuard);
    ResultCode CompanionProcessCheck(const CompanionProcessCheckInput &input, const InteractionDesc &desc,
        std::vector<uint8_t> &outCompanionCheckResponse);
    std::optional<SyncDeviceStatusReply> BuildSyncDeviceStatusReply(const UserKey &companionUserKey,
        const LocalDeviceProfile &localProfile, const InteractionDesc &desc);
    void SetCompanionDeviceKeyUserId(SyncDeviceStatusReply &syncReply, const UserKey &companionUserKey);
    CompanionProcessCheckInput BuildCompanionProcessCheckInput(const HostBindingStatus &hostBindingStatus,
        const SyncDeviceStatusRequest &syncRequest, const std::vector<ProtocolId> &companionProtocolList,
        const LocalDeviceProfile &localProfile, const BindingSignatureProof &bindingSignatureProof);
    UserKey QueryActiveUserKey();
    std::optional<HostBindingStatus> QueryHostBindingStatus(const UserKey &companionUserKey,
        const DeviceKey &hostDeviceKey);
    void GateBindingProofAgainstEnrolledProtocol(const SyncDeviceStatusRequest &syncRequest, InteractionDesc &desc,
        InteractionEventCollector &eventCollector, std::optional<HostBindingStatus> &hostBindingStatus);
    ResultCode ProcessBindingCheck(const SyncDeviceStatusRequest &syncRequest,
        const std::optional<HostBindingStatus> &hostBindingStatus, const LocalDeviceProfile &localProfile,
        const InteractionDesc &desc, SyncDeviceStatusReply &syncReply);
    void PublishPeerSyncedEvent(const DeviceKey &hostDeviceKey);
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_SYNC_DEVICE_STATUS_HANDLER_H
