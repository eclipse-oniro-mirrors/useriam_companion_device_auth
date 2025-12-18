/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "companion_device_auth_client_impl.h"

#include <cinttypes>

#include "system_ability_definition.h"

#include "iam_logger.h"
#include "iam_para2str.h"
#include "ipc_available_device_status_callback_service.h"
#include "ipc_client_utils.h"
#include "ipc_continuous_auth_status_callback_service.h"
#include "ipc_device_select_callback_service.h"
#include "ipc_template_status_callback_service.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH_SDK"
namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
int32_t CompanionDeviceAuthClientImpl::RegisterDeviceSelectCallback(
    const std::shared_ptr<IDeviceSelectCallback> &callback)
{
    IAM_LOGI("start");
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    sptr<IIpcDeviceSelectCallback> wrapper(new (std::nothrow) IpcDeviceSelectCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("fail to create wrapper");
        return GENERAL_ERROR;
    }

    int32_t ret;
    int32_t ipcRet = proxy->RegisterDeviceSelectCallback(wrapper, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("RegisterDeviceSelectCallback fail, ret:%{public}d", ret);
    }

    return ret;
}

int32_t CompanionDeviceAuthClientImpl::UnregisterDeviceSelectCallback()
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    int32_t ret;
    int32_t ipcRet = proxy->UnregisterDeviceSelectCallback(ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("UnregisterDeviceSelectCallback fail, ret:%{public}d", ret);
    }

    return ret;
}

int32_t CompanionDeviceAuthClientImpl::UpdateTemplateEnabledBusinessIds(const uint64_t templateId,
    const std::vector<int32_t> enabledBusinessIds)
{
    IAM_LOGI("start, templateId:%{public}" PRIu64 ", enabledBusinessIds size:%{public}d", templateId,
        static_cast<int32_t>(enabledBusinessIds.size()));
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    int32_t ret;
    int32_t ipcRet = proxy->UpdateTemplateEnabledBusinessIds(templateId, enabledBusinessIds, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("UpdateTemplateEnabledBusinessIds fail, ret:%{public}d", ret);
    }

    return ret;
}

void CompanionDeviceAuthClientImpl::PrintIpcTemplateStatus(const IpcTemplateStatus &ipcTemplateStatus)
{
    IAM_LOGI("deviceIdType:%{public}d, deviceId:%{public}s, deviceUserId:%{public}d",
        ipcTemplateStatus.deviceStatus.deviceKey.deviceIdType,
        GetMaskedString(ipcTemplateStatus.deviceStatus.deviceKey.deviceId).c_str(),
        ipcTemplateStatus.deviceStatus.deviceKey.deviceUserId);

    IAM_LOGI("deviceUserName:%{public}s, deviceModelInfo:%{public}s, deviceName:%{public}s, isOnline:%{public}d, "
             "supportedBusinessIds size:%{public}d",
        ipcTemplateStatus.deviceStatus.deviceUserName.c_str(), ipcTemplateStatus.deviceStatus.deviceModelInfo.c_str(),
        ipcTemplateStatus.deviceStatus.deviceName.c_str(),
        static_cast<int32_t>(ipcTemplateStatus.deviceStatus.isOnline),
        static_cast<int32_t>(ipcTemplateStatus.deviceStatus.supportedBusinessIds.size()));

    IAM_LOGI("templateId:%{public}d, isConfirmed:%{public}d, isValid:%{public}d, localUserId:%{public}d, "
             "addedTime:%{public}" PRId64 ", enabledBusinessIds size:%{public}d",
        static_cast<int32_t>(ipcTemplateStatus.templateId), static_cast<int32_t>(ipcTemplateStatus.isConfirmed),
        static_cast<int32_t>(ipcTemplateStatus.isValid), ipcTemplateStatus.localUserId, ipcTemplateStatus.addedTime,
        static_cast<int32_t>(ipcTemplateStatus.enabledBusinessIds.size()));
}

int32_t CompanionDeviceAuthClientImpl::GetTemplateStatus(std::vector<ClientTemplateStatus> &templateStatusList)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    int32_t ret;
    std::vector<IpcTemplateStatus> ipcTemplateStatusList;
    int32_t ipcRet = proxy->GetTemplateStatus(ipcTemplateStatusList, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("GetTemplateStatus fail, ret:%{public}d", ret);
        return ret;
    }

    IAM_LOGI("ipcTemplateStatusList size:%{public}d", static_cast<int32_t>(ipcTemplateStatusList.size()));
    for (const auto &ipcTemplateStatus : ipcTemplateStatusList) {
        PrintIpcTemplateStatus(ipcTemplateStatus);

        ClientDeviceKey clientDeviceKey;
        clientDeviceKey.deviceIdType = ipcTemplateStatus.deviceStatus.deviceKey.deviceIdType;
        clientDeviceKey.deviceId = ipcTemplateStatus.deviceStatus.deviceKey.deviceId;
        clientDeviceKey.deviceUserId = ipcTemplateStatus.deviceStatus.deviceKey.deviceUserId;

        ClientDeviceStatus clientDeviceStatus;
        clientDeviceStatus.deviceKey = clientDeviceKey;
        clientDeviceStatus.deviceUserName = ipcTemplateStatus.deviceStatus.deviceUserName;
        clientDeviceStatus.deviceModelInfo = ipcTemplateStatus.deviceStatus.deviceModelInfo;
        clientDeviceStatus.deviceName = ipcTemplateStatus.deviceStatus.deviceName;
        clientDeviceStatus.isOnline = ipcTemplateStatus.deviceStatus.isOnline;
        clientDeviceStatus.supportedBusinessIds = ipcTemplateStatus.deviceStatus.supportedBusinessIds;

        ClientTemplateStatus clientTemplateStatus;
        clientTemplateStatus.templateId = ipcTemplateStatus.templateId;
        clientTemplateStatus.isConfirmed = ipcTemplateStatus.isConfirmed;
        clientTemplateStatus.isValid = ipcTemplateStatus.isValid;
        clientTemplateStatus.localUserId = ipcTemplateStatus.localUserId;
        clientTemplateStatus.addedTime = ipcTemplateStatus.addedTime;
        clientTemplateStatus.enabledBusinessIds = ipcTemplateStatus.enabledBusinessIds;
        clientTemplateStatus.deviceStatus = clientDeviceStatus;
        templateStatusList.push_back(clientTemplateStatus);
    }

    return ret;
}

int32_t CompanionDeviceAuthClientImpl::SubscribeTemplateStatusChange(const int32_t localUserId,
    const std::shared_ptr<ITemplateStatusCallback> &callback)
{
    IAM_LOGI("start, localUserId:%{public}d", localUserId);
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    sptr<IIpcTemplateStatusCallback> wrapper(new (std::nothrow) IpcTemplateStatusCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return GENERAL_ERROR;
    }

    int32_t ret;
    int32_t ipcRet = proxy->SubscribeTemplateStatusChange(localUserId, wrapper, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("SubscribeTemplateStatusChange fail, ret:%{public}d", ret);
    }

    return ret;
}

int32_t CompanionDeviceAuthClientImpl::UnsubscribeTemplateStatusChange(
    const std::shared_ptr<ITemplateStatusCallback> &callback)
{
    IAM_LOGI("start");
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    sptr<IIpcTemplateStatusCallback> wrapper(new (std::nothrow) IpcTemplateStatusCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return GENERAL_ERROR;
    }

    int32_t ret;
    int32_t ipcRet = proxy->UnsubscribeTemplateStatusChange(wrapper, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("UnsubscribeTemplateStatusChange fail, ret:%{public}d", ret);
    }

    return ret;
}

int32_t CompanionDeviceAuthClientImpl::SubscribeAvailableDeviceStatus(const int32_t localUserId,
    const std::shared_ptr<IAvailableDeviceStatusCallback> &callback)
{
    IAM_LOGI("start, localUserId:%{public}d", localUserId);
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    sptr<IIpcAvailableDeviceStatusCallback> wrapper(
        new (std::nothrow) IpcAvailableDeviceStatusCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return GENERAL_ERROR;
    }

    int32_t ret;
    int32_t ipcRet = proxy->SubscribeAvailableDeviceStatus(localUserId, wrapper, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("SubscribeAvailableDeviceStatus fail, ret:%{public}d", ret);
    }

    return ret;
}

int32_t CompanionDeviceAuthClientImpl::UnsubscribeAvailableDeviceStatus(
    const std::shared_ptr<IAvailableDeviceStatusCallback> &callback)
{
    IAM_LOGI("start");
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    sptr<IIpcAvailableDeviceStatusCallback> wrapper(
        new (std::nothrow) IpcAvailableDeviceStatusCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return GENERAL_ERROR;
    }

    int32_t ret;
    int32_t ipcRet = proxy->UnsubscribeAvailableDeviceStatus(wrapper, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("UnsubscribeAvailableDeviceStatus fail, ret:%{public}d", ret);
    }

    return ret;
}

int32_t CompanionDeviceAuthClientImpl::SubscribeContinuousAuthStatusChange(const int32_t localUserId,
    const std::shared_ptr<IContinuousAuthStatusCallback> &callback, const std::optional<uint64_t> templateId)
{
    IAM_LOGI("start, localUserId:%{public}d", localUserId);
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }
    sptr<IIpcContinuousAuthStatusCallback> wrapper(new (std::nothrow) IpcContinuousAuthStatusCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return GENERAL_ERROR;
    }

    IpcSubscribeContinuousAuthStatusParam param;
    param.localUserId = localUserId;
    param.hasTemplateId = false;
    if (templateId.has_value()) {
        IAM_LOGI("templateId:%{public}d", static_cast<int32_t>(templateId.value()));
        param.hasTemplateId = true;
        param.templateId = templateId.value();
    } else {
        IAM_LOGI("templateId not exist");
    }

    int32_t ret;
    int32_t ipcRet = proxy->SubscribeContinuousAuthStatusChange(param, wrapper, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("SubscribeContinuousAuthStatusChange fail, ret:%{public}d", ret);
    }

    return ret;
}

int32_t CompanionDeviceAuthClientImpl::UnsubscribeContinuousAuthStatusChange(
    const std::shared_ptr<IContinuousAuthStatusCallback> &callback)
{
    IAM_LOGI("start");
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }
    sptr<IIpcContinuousAuthStatusCallback> wrapper(new (std::nothrow) IpcContinuousAuthStatusCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return GENERAL_ERROR;
    }

    int32_t ret;
    int32_t ipcRet = proxy->UnsubscribeContinuousAuthStatusChange(wrapper, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("UnsubscribeContinuousAuthStatusChange fail, ret:%{public}d", ret);
    }

    return ret;
}

sptr<ICompanionDeviceAuth> CompanionDeviceAuthClientImpl::GetProxy()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }

    sptr<IRemoteObject> obj = IpcClientUtils::GetRemoteObject(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH);
    if (obj == nullptr) {
        IAM_LOGE("remote object is null");
        return proxy_;
    }
    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) CompanionDeviceAuthClientImplDeathRecipient());
    if ((dr == nullptr) || (obj->IsProxyObject() && !obj->AddDeathRecipient(dr))) {
        IAM_LOGE("add death recipient fail");
        return proxy_;
    }

    proxy_ = iface_cast<ICompanionDeviceAuth>(obj);
    deathRecipient_ = dr;
    return proxy_;
}

void CompanionDeviceAuthClientImpl::ResetProxy(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (proxy_ == nullptr) {
        IAM_LOGE("proxy_ is null");
        return;
    }

    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        IAM_LOGI("need reset");
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
        deathRecipient_ = nullptr;
    }
    IAM_LOGI("success");
}

void CompanionDeviceAuthClientImpl::CompanionDeviceAuthClientImplDeathRecipient::OnRemoteDied(
    const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    CompanionDeviceAuthClientImpl::Instance().ResetProxy(remote);
}

CompanionDeviceAuthClientImpl &CompanionDeviceAuthClientImpl::Instance()
{
    static CompanionDeviceAuthClientImpl impl;
    return impl;
}

CompanionDeviceAuthClient &CompanionDeviceAuthClient::GetInstance()
{
    return CompanionDeviceAuthClientImpl::Instance();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS