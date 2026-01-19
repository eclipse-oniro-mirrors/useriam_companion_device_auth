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

#include "request_factory_impl.h"

#include <new>

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_add_companion_request.h"
#include "companion_auth_maintain_state_change_request.h"
#include "companion_delegate_auth_request.h"
#include "companion_issue_token_request.h"
#include "companion_obtain_token_request.h"
#include "companion_revoke_token_request.h"
#include "host_add_companion_request.h"
#include "host_delegate_auth_request.h"
#include "host_issue_token_request.h"
#include "host_mix_auth_request.h"
#include "host_obtain_token_request.h"
#include "host_remove_host_binding_request.h"
#include "host_single_mix_auth_request.h"
#include "host_sync_device_status_request.h"
#include "host_token_auth_request.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
std::shared_ptr<RequestFactoryImpl> RequestFactoryImpl::Create()
{
    auto factory = std::shared_ptr<RequestFactoryImpl>(new (std::nothrow) RequestFactoryImpl());
    ENSURE_OR_RETURN_VAL(factory != nullptr, nullptr);
    return factory;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostAddCompanionRequest(ScheduleId scheduleId,
    const std::vector<uint8_t> &fwkMsg, uint32_t tokenId, FwkResultCallback &&requestCallback)
{
    return std::make_shared<HostAddCompanionRequest>(scheduleId, fwkMsg, tokenId, std::move(requestCallback));
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostTokenAuthRequest(ScheduleId scheduleId,
    const std::vector<uint8_t> &fwkMsg, UserId hostUserId, TemplateId templateId, FwkResultCallback &&requestCallback)
{
    return std::make_shared<HostTokenAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
        std::move(requestCallback));
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostRemoveHostBindingRequest(UserId hostUserId,
    TemplateId templateId, const DeviceKey &companionDeviceKey)
{
    return std::make_shared<HostRemoveHostBindingRequest>(hostUserId, templateId, companionDeviceKey);
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostSyncDeviceStatusRequest(UserId hostUserId,
    const DeviceKey &companionDeviceKey, const std::string &companionDeviceName, SyncDeviceStatusCallback &&callback)
{
    return std::make_shared<HostSyncDeviceStatusRequest>(hostUserId, companionDeviceKey, companionDeviceName,
        std::move(callback));
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostIssueTokenRequest(UserId hostUserId, TemplateId templateId,
    const std::vector<uint8_t> &fwkUnlockMsg)
{
    return std::make_shared<HostIssueTokenRequest>(hostUserId, templateId, fwkUnlockMsg);
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostDelegateAuthRequest(ScheduleId scheduleId,
    const std::vector<uint8_t> &fwkMsg, UserId hostUserId, TemplateId templateId, FwkResultCallback &&requestCallback)
{
    return std::make_shared<HostDelegateAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
        std::move(requestCallback));
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateCompanionAddCompanionRequest(const std::string &connectionName,
    const Attributes &request, OnMessageReply replyCallback, const DeviceKey &hostDeviceKey)
{
    return std::make_shared<CompanionAddCompanionRequest>(connectionName, request, replyCallback, hostDeviceKey);
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateCompanionIssueTokenRequest(const std::string &connectionName,
    const Attributes &request, OnMessageReply replyCallback, const DeviceKey &hostDeviceKey)
{
    return std::make_shared<CompanionIssueTokenRequest>(connectionName, request, replyCallback, hostDeviceKey);
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostObtainTokenRequest(const std::string &connectionName,
    const Attributes &request, OnMessageReply replyCallback, const DeviceKey &companionDeviceKey)
{
    return std::make_shared<HostObtainTokenRequest>(connectionName, request, replyCallback, companionDeviceKey);
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateCompanionObtainTokenRequest(const DeviceKey &hostDeviceKey,
    const std::vector<uint8_t> &fwkUnlockMsg)
{
    return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateCompanionDelegateAuthRequest(const std::string &connectionName,
    UserId companionUserId, const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &startDelegateAuthRequest)
{
    return std::make_shared<CompanionDelegateAuthRequest>(connectionName, companionUserId, hostDeviceKey,
        startDelegateAuthRequest);
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateCompanionRevokeTokenRequest(UserId companionUserId,
    const DeviceKey &hostDeviceKey)
{
    return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateCompanionAuthMaintainStateChangeRequest(
    const DeviceKey &hostDeviceKey, bool authStateMaintain)
{
    return std::make_shared<CompanionAuthMaintainStateChangeRequest>(hostDeviceKey, authStateMaintain);
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostMixAuthRequest(ScheduleId scheduleId,
    std::vector<uint8_t> fwkMsg, UserId hostUserId, std::vector<TemplateId> templateIdList,
    FwkResultCallback &&requestCallback)
{
    return std::make_shared<HostMixAuthRequest>(scheduleId, fwkMsg, hostUserId, templateIdList,
        std::move(requestCallback));
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostSingleMixAuthRequest(ScheduleId scheduleId,
    std::vector<uint8_t> fwkMsg, UserId hostUserId, TemplateId templateId, FwkResultCallback &&requestCallback)
{
    return std::make_shared<HostSingleMixAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
        std::move(requestCallback));
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
