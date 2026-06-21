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

#include <cinttypes>
#include <new>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "companion_add_companion_request.h"
#include "companion_delegate_auth_request.h"
#include "companion_issue_token_request.h"
#include "companion_manager.h"
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
#define LOG_FILE_ID LOG_FILE_REQUEST_FACTORY_IMPL

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
    const std::vector<uint8_t> &fwkMsg, uint32_t tokenId, const std::string &additionalInfo,
    FwkResultCallback &&requestCallback)
{
    auto request = std::make_shared<HostAddCompanionRequest>(scheduleId, fwkMsg, tokenId, additionalInfo,
        std::move(requestCallback));
    ENSURE_OR_RETURN_VAL(request != nullptr, nullptr);
    return request;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostTokenAuthRequest(const AuthRequestParams &params,
    FwkResultCallback &&requestCallback)
{
    auto companionStatus = GetCompanionManager().GetCompanionStatus(params.templateId);
    if (!companionStatus.has_value()) {
        IAM_LOGE("GetCompanionStatus failed for templateId %{public}s", GET_MASKED_NUM_CSTR(params.templateId));
        return nullptr;
    }
    const DeviceKey &companionDeviceKey = companionStatus->companionDeviceStatus.deviceKey;

    auto request = std::make_shared<HostTokenAuthRequest>(params, companionDeviceKey, std::move(requestCallback));
    ENSURE_OR_RETURN_VAL(request != nullptr, nullptr);
    return request;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostRemoveHostBindingRequest(UserId hostUserId,
    TemplateId templateId, const DeviceKey &companionDeviceKey)
{
    auto request = std::make_shared<HostRemoveHostBindingRequest>(hostUserId, templateId, companionDeviceKey);
    ENSURE_OR_RETURN_VAL(request != nullptr, nullptr);
    return request;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostSyncDeviceStatusRequest(UserId hostUserId,
    const DeviceKey &companionDeviceKey, const std::string &companionDeviceName, SyncDeviceStatusCallback &&callback)
{
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId, companionDeviceKey, companionDeviceName,
        std::move(callback));
    ENSURE_OR_RETURN_VAL(request != nullptr, nullptr);
    return request;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostIssueTokenRequest(UserId hostUserId, TemplateId templateId,
    uint32_t lockStateAuthTypeValue, const std::vector<uint8_t> &fwkUnlockMsg)
{
    auto companionStatus = GetCompanionManager().GetCompanionStatus(templateId);
    if (!companionStatus.has_value()) {
        IAM_LOGE("GetCompanionStatus failed for templateId %{public}s", GET_MASKED_NUM_CSTR(templateId));
        return nullptr;
    }
    const DeviceKey &companionDeviceKey = companionStatus->companionDeviceStatus.deviceKey;

    auto request = std::make_shared<HostIssueTokenRequest>(hostUserId, templateId, lockStateAuthTypeValue, fwkUnlockMsg,
        companionDeviceKey);
    ENSURE_OR_RETURN_VAL(request != nullptr, nullptr);
    return request;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostDelegateAuthRequest(const AuthRequestParams &params,
    FwkResultCallback &&requestCallback)
{
    auto companionStatus = GetCompanionManager().GetCompanionStatus(params.templateId);
    if (!companionStatus.has_value()) {
        IAM_LOGE("GetCompanionStatus failed for templateId %{public}s", GET_MASKED_NUM_CSTR(params.templateId));
        return nullptr;
    }
    const DeviceKey &companionDeviceKey = companionStatus->companionDeviceStatus.deviceKey;

    auto request = std::make_shared<HostDelegateAuthRequest>(params, companionDeviceKey, std::move(requestCallback));
    ENSURE_OR_RETURN_VAL(request != nullptr, nullptr);
    return request;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateCompanionAddCompanionRequest(const std::string &connectionName,
    const Attributes &requestAttr, OnMessageReply &&replyCallback, const DeviceKey &hostDeviceKey)
{
    auto requestObj = std::make_shared<CompanionAddCompanionRequest>(connectionName, requestAttr,
        std::move(replyCallback), hostDeviceKey);
    ENSURE_OR_RETURN_VAL(requestObj != nullptr, nullptr);
    return requestObj;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateCompanionIssueTokenRequest(const std::string &connectionName,
    const Attributes &requestAttr, OnMessageReply &&replyCallback, const DeviceKey &hostDeviceKey)
{
    auto requestObj = std::make_shared<CompanionIssueTokenRequest>(connectionName, requestAttr,
        std::move(replyCallback), hostDeviceKey);
    ENSURE_OR_RETURN_VAL(requestObj != nullptr, nullptr);
    return requestObj;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostObtainTokenRequest(const std::string &connectionName,
    const Attributes &requestAttr, OnMessageReply &&replyCallback, const DeviceKey &companionDeviceKey)
{
    auto requestObj = std::make_shared<HostObtainTokenRequest>(connectionName, requestAttr, std::move(replyCallback),
        companionDeviceKey);
    ENSURE_OR_RETURN_VAL(requestObj != nullptr, nullptr);
    return requestObj;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateCompanionObtainTokenRequest(const DeviceKey &hostDeviceKey,
    uint32_t lockStateAuthTypeValue, const std::vector<uint8_t> &fwkUnlockMsg)
{
    auto request = std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, lockStateAuthTypeValue, fwkUnlockMsg);
    ENSURE_OR_RETURN_VAL(request != nullptr, nullptr);
    return request;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateCompanionDelegateAuthRequest(const std::string &connectionName,
    UserId companionUserId, const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &startDelegateAuthRequest,
    const ComapionDelegateAuthParam &delegateAuthParam)
{
    auto request = std::make_shared<CompanionDelegateAuthRequest>(connectionName, companionUserId, hostDeviceKey,
        startDelegateAuthRequest, delegateAuthParam);
    ENSURE_OR_RETURN_VAL(request != nullptr, nullptr);
    return request;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateCompanionRevokeTokenRequest(UserId companionUserId,
    const DeviceKey &hostDeviceKey, const std::string &triggerReason)
{
    auto request = std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey, triggerReason);
    ENSURE_OR_RETURN_VAL(request != nullptr, nullptr);
    return request;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostMixAuthRequest(const HostMixAuthParams &params,
    FwkResultCallback &&requestCallback)
{
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(requestCallback));
    ENSURE_OR_RETURN_VAL(request != nullptr, nullptr);
    return request;
}

std::shared_ptr<IRequest> RequestFactoryImpl::CreateHostSingleMixAuthRequest(const AuthRequestParams &params,
    const DeviceKey &companionDeviceKey, FwkResultCallback &&requestCallback)
{
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, companionDeviceKey, std::move(requestCallback));
    ENSURE_OR_RETURN_VAL(request != nullptr, nullptr);
    return request;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
