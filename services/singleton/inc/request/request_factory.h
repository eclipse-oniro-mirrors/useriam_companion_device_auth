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

#ifndef COMPANION_DEVICE_AUTH_REQUEST_FACTORY_H
#define COMPANION_DEVICE_AUTH_REQUEST_FACTORY_H

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "cda_attributes.h"
#include "cross_device_common.h"
#include "irequest.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SyncDeviceStatusCallback = std::function<void(ResultCode result, const SyncDeviceStatus &syncDeviceStatus)>;

class IRequestFactory : public NoCopyable {
public:
    virtual ~IRequestFactory() = default;

    virtual std::shared_ptr<IRequest> CreateHostAddCompanionRequest(ScheduleId scheduleId,
        const std::vector<uint8_t> &fwkMsg, uint32_t tokenId, FwkResultCallback &&requestCallback) = 0;
    virtual std::shared_ptr<IRequest> CreateHostTokenAuthRequest(ScheduleId scheduleId,
        const std::vector<uint8_t> &fwkMsg, UserId hostUserId, TemplateId templateId,
        FwkResultCallback &&requestCallback) = 0;
    virtual std::shared_ptr<IRequest> CreateHostRemoveHostBindingRequest(UserId hostUserId, TemplateId templateId,
        const DeviceKey &companionDeviceKey) = 0;
    virtual std::shared_ptr<IRequest> CreateHostSyncDeviceStatusRequest(UserId hostUserId,
        const DeviceKey &companionDeviceKey, const std::string &companionDeviceName,
        SyncDeviceStatusCallback &&callback) = 0;
    virtual std::shared_ptr<IRequest> CreateHostIssueTokenRequest(UserId hostUserId, TemplateId templateId,
        const std::vector<uint8_t> &fwkUnlockMsg) = 0;
    virtual std::shared_ptr<IRequest> CreateHostDelegateAuthRequest(ScheduleId scheduleId,
        const std::vector<uint8_t> &fwkMsg, UserId hostUserId, TemplateId templateId,
        FwkResultCallback &&requestCallback) = 0;
    virtual std::shared_ptr<IRequest> CreateCompanionAddCompanionRequest(const std::string &connectionName,
        const Attributes &request, OnMessageReply replyCallback, const DeviceKey &hostDeviceKey) = 0;
    virtual std::shared_ptr<IRequest> CreateCompanionIssueTokenRequest(const std::string &connectionName,
        const Attributes &request, OnMessageReply replyCallback, const DeviceKey &hostDeviceKey) = 0;
    virtual std::shared_ptr<IRequest> CreateHostObtainTokenRequest(const std::string &connectionName,
        const Attributes &request, OnMessageReply replyCallback, const DeviceKey &companionDeviceKey) = 0;
    virtual std::shared_ptr<IRequest> CreateCompanionObtainTokenRequest(const DeviceKey &hostDeviceKey,
        const std::vector<uint8_t> &fwkUnlockMsg) = 0;
    virtual std::shared_ptr<IRequest> CreateCompanionDelegateAuthRequest(const std::string &connectionName,
        UserId companionUserId, const DeviceKey &hostDeviceKey,
        const std::vector<uint8_t> &startDelegateAuthRequest) = 0;
    virtual std::shared_ptr<IRequest> CreateCompanionRevokeTokenRequest(UserId companionUserId,
        const DeviceKey &hostDeviceKey) = 0;
    virtual std::shared_ptr<IRequest> CreateCompanionAuthMaintainStateChangeRequest(const DeviceKey &hostDeviceKey,
        bool authStateMaintain) = 0;
    virtual std::shared_ptr<IRequest> CreateHostMixAuthRequest(ScheduleId scheduleId, std::vector<uint8_t> fwkMsg,
        UserId hostUserId, std::vector<TemplateId> templateIdList, FwkResultCallback &&requestCallback) = 0;
    virtual std::shared_ptr<IRequest> CreateHostSingleMixAuthRequest(ScheduleId scheduleId, std::vector<uint8_t> fwkMsg,
        UserId hostUserId, TemplateId templateId, FwkResultCallback &&requestCallback) = 0;

protected:
    IRequestFactory() = default;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_REQUEST_FACTORY_H
