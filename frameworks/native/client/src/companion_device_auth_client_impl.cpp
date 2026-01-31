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
#include <memory>

#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "scope_guard.h"

#define LOG_TAG "CDA_SDK"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

CompanionDeviceAuthClientImpl::CompanionDeviceAuthClientImpl()
{
}

#ifdef ENABLE_TEST
void CompanionDeviceAuthClientImpl::SetProxy(const sptr<ICompanionDeviceAuth> &proxy)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    proxy_ = proxy;
}
#endif // ENABLE_TEST

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

    sptr<IpcDeviceSelectCallbackService> wrapper(new (std::nothrow) IpcDeviceSelectCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("fail to create wrapper");
        return GENERAL_ERROR;
    }

    int32_t ret = GENERAL_ERROR;
    int32_t ipcRet = proxy->RegisterDeviceSelectCallback(wrapper, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("RegisterDeviceSelectCallback fail, ret:%{public}d", ret);
        return ret;
    }

    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        deviceSelectCallback_ = callback;
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

    int32_t ret = GENERAL_ERROR;
    int32_t ipcRet = proxy->UnregisterDeviceSelectCallback(ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("UnregisterDeviceSelectCallback fail, ret:%{public}d", ret);
    }

    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        deviceSelectCallback_ = nullptr;
    }
    return ret;
}

int32_t CompanionDeviceAuthClientImpl::UpdateTemplateEnabledBusinessIds(
    uint64_t templateId, const std::vector<int32_t> &enabledBusinessIds)
{
    IAM_LOGI("start, templateId:%{public}s, enabledBusinessIds size:%{public}zu", GET_MASKED_NUM_CSTR(templateId),
        enabledBusinessIds.size());
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    int32_t ret = GENERAL_ERROR;
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
             "supportedBusinessIds size:%{public}zu",
        ipcTemplateStatus.deviceStatus.deviceUserName.c_str(), ipcTemplateStatus.deviceStatus.deviceModelInfo.c_str(),
        ipcTemplateStatus.deviceStatus.deviceName.c_str(), ipcTemplateStatus.deviceStatus.isOnline,
        ipcTemplateStatus.deviceStatus.supportedBusinessIds.size());

    IAM_LOGI("templateId:%{public}s, isConfirmed:%{public}d, isValid:%{public}d, userId:%{public}d, "
             "addedTime:%{public}" PRId64 ", enabledBusinessIds size:%{public}zu",
        GET_MASKED_NUM_CSTR(ipcTemplateStatus.templateId), ipcTemplateStatus.isConfirmed, ipcTemplateStatus.isValid,
        ipcTemplateStatus.localUserId, ipcTemplateStatus.addedTime, ipcTemplateStatus.enabledBusinessIds.size());
}

int32_t CompanionDeviceAuthClientImpl::GetTemplateStatus(
    int32_t userId, std::vector<ClientTemplateStatus> &templateStatusList)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    int32_t ret = GENERAL_ERROR;
    std::vector<IpcTemplateStatus> ipcTemplateStatusList;
    int32_t ipcRet = proxy->GetTemplateStatus(userId, ipcTemplateStatusList, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("GetTemplateStatus fail, ret:%{public}d", ret);
        return ret;
    }

    IAM_LOGI("ipcTemplateStatusList size:%{public}zu", ipcTemplateStatusList.size());
    for (const auto &ipcTemplateStatus : ipcTemplateStatusList) {
        PrintIpcTemplateStatus(ipcTemplateStatus);

        ClientDeviceKey clientDeviceKey {};
        clientDeviceKey.deviceIdType = ipcTemplateStatus.deviceStatus.deviceKey.deviceIdType;
        clientDeviceKey.deviceId = ipcTemplateStatus.deviceStatus.deviceKey.deviceId;
        clientDeviceKey.deviceUserId = ipcTemplateStatus.deviceStatus.deviceKey.deviceUserId;

        ClientDeviceStatus clientDeviceStatus {};
        clientDeviceStatus.deviceKey = clientDeviceKey;
        clientDeviceStatus.deviceUserName = ipcTemplateStatus.deviceStatus.deviceUserName;
        clientDeviceStatus.deviceModelInfo = ipcTemplateStatus.deviceStatus.deviceModelInfo;
        clientDeviceStatus.deviceName = ipcTemplateStatus.deviceStatus.deviceName;
        clientDeviceStatus.isOnline = ipcTemplateStatus.deviceStatus.isOnline;
        clientDeviceStatus.supportedBusinessIds = ipcTemplateStatus.deviceStatus.supportedBusinessIds;

        ClientTemplateStatus clientTemplateStatus {};
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

int32_t CompanionDeviceAuthClientImpl::SubscribeTemplateStatusChangeInner(
    sptr<IpcTemplateStatusCallbackService> callback)
{
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    int32_t ret = GENERAL_ERROR;
    int32_t ipcRet = proxy->SubscribeTemplateStatusChange(callback->GetUserId(), callback, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }
    return ret;
}

int32_t CompanionDeviceAuthClientImpl::SubscribeTemplateStatusChange(
    int32_t userId, const std::shared_ptr<ITemplateStatusCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    sptr<IpcTemplateStatusCallbackService> wrapper(
        new (std::nothrow) IpcTemplateStatusCallbackService(userId, callback));
    int32_t ret = SubscribeTemplateStatusChangeInner(wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("SubscribeTemplateStatusChange fail, ret:%{public}d", ret);
        return ret;
    }

    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        templateStatusCallbacks_.push_back(wrapper);
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

    sptr<IpcTemplateStatusCallbackService> ipcCallback(nullptr);
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        auto it = std::find_if(templateStatusCallbacks_.begin(), templateStatusCallbacks_.end(),
            [&callback](const auto &item) { return item && item->GetCallback() == callback; });
        if (it == templateStatusCallbacks_.end()) {
            IAM_LOGE("callback not found");
            return GENERAL_ERROR;
        }
        ipcCallback = *it;
    }

    int32_t ret = GENERAL_ERROR;
    int32_t ipcRet = proxy->UnsubscribeTemplateStatusChange(ipcCallback, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("UnsubscribeTemplateStatusChange fail, ret:%{public}d", ret);
        return ret;
    }

    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        auto it = std::find_if(templateStatusCallbacks_.begin(), templateStatusCallbacks_.end(),
            [&ipcCallback](const auto &item) { return item == ipcCallback; });
        if (it != templateStatusCallbacks_.end()) {
            templateStatusCallbacks_.erase(it);
        }
    }
    return ret;
}

int32_t CompanionDeviceAuthClientImpl::SubscribeAvailableDeviceStatusInner(
    sptr<IpcAvailableDeviceStatusCallbackService> callback)
{
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    int32_t ret = GENERAL_ERROR;
    int32_t ipcRet = proxy->SubscribeAvailableDeviceStatus(callback->GetUserId(), callback, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }
    return ret;
}

int32_t CompanionDeviceAuthClientImpl::SubscribeAvailableDeviceStatus(int32_t userId,
    const std::shared_ptr<IAvailableDeviceStatusCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    sptr<IpcAvailableDeviceStatusCallbackService> wrapper(
        new (std::nothrow) IpcAvailableDeviceStatusCallbackService(userId, callback));
    int32_t ret = SubscribeAvailableDeviceStatusInner(wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("SubscribeAvailableDeviceStatus fail, ret:%{public}d", ret);
        return ret;
    }

    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        availableDeviceStatusCallbacks_.push_back(wrapper);
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

    sptr<IpcAvailableDeviceStatusCallbackService> ipcCallback(nullptr);
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        auto it = std::find_if(availableDeviceStatusCallbacks_.begin(), availableDeviceStatusCallbacks_.end(),
            [&callback](const auto &item) { return item && item->GetCallback() == callback; });
        if (it == availableDeviceStatusCallbacks_.end()) {
            IAM_LOGE("callback not found");
            return GENERAL_ERROR;
        }
        ipcCallback = *it;
    }
    int32_t ret = GENERAL_ERROR;
    int32_t ipcRet = proxy->UnsubscribeAvailableDeviceStatus(ipcCallback, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("UnsubscribeAvailableDeviceStatus fail, ret:%{public}d", ret);
        return ret;
    }

    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        auto it = std::find_if(availableDeviceStatusCallbacks_.begin(), availableDeviceStatusCallbacks_.end(),
            [&ipcCallback](const auto &item) { return item == ipcCallback; });
        if (it != availableDeviceStatusCallbacks_.end()) {
            availableDeviceStatusCallbacks_.erase(it);
        }
    }
    return ret;
}

int32_t CompanionDeviceAuthClientImpl::SubscribeContinuousAuthStatusChangeInner(
    sptr<IpcContinuousAuthStatusCallbackService> callback)
{
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    auto templateId = callback->GetTemplateId();

    IpcSubscribeContinuousAuthStatusParam param {};
    param.localUserId = callback->GetUserId();
    param.hasTemplateId = false;
    if (templateId.has_value()) {
        IAM_LOGI("templateId:%{public}s", GET_MASKED_NUM_CSTR(templateId.value()));
        param.hasTemplateId = true;
        param.templateId = templateId.value();
    } else {
        IAM_LOGI("templateId not exist");
    }

    int32_t ret = GENERAL_ERROR;
    int32_t ipcRet = proxy->SubscribeContinuousAuthStatusChange(param, callback, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }
    return ret;
}

int32_t CompanionDeviceAuthClientImpl::SubscribeContinuousAuthStatusChange(int32_t userId,
    std::optional<uint64_t> templateId, const std::shared_ptr<IContinuousAuthStatusCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    sptr<IpcContinuousAuthStatusCallbackService> wrapper(
        new (std::nothrow) IpcContinuousAuthStatusCallbackService(userId, templateId, callback));
    int32_t ret = SubscribeContinuousAuthStatusChangeInner(wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("SubscribeContinuousAuthStatusChange fail, ret:%{public}d", ret);
        return ret;
    }

    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        continuousAuthStatusCallbacks_.push_back(wrapper);
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
    sptr<IpcContinuousAuthStatusCallbackService> ipcCallback(nullptr);
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        auto it = std::find_if(continuousAuthStatusCallbacks_.begin(), continuousAuthStatusCallbacks_.end(),
            [&callback](const auto &item) { return item && item->GetCallback() == callback; });
        if (it == continuousAuthStatusCallbacks_.end()) {
            IAM_LOGE("callback not found");
            return GENERAL_ERROR;
        }
        ipcCallback = *it;
    }
    int32_t ret = GENERAL_ERROR;
    int32_t ipcRet = proxy->UnsubscribeContinuousAuthStatusChange(ipcCallback, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("UnsubscribeContinuousAuthStatusChange fail, ret:%{public}d", ret);
        return ret;
    }

    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        auto it = std::find_if(continuousAuthStatusCallbacks_.begin(), continuousAuthStatusCallbacks_.end(),
            [&ipcCallback](const auto &item) { return item == ipcCallback; });
        if (it != continuousAuthStatusCallbacks_.end()) {
            continuousAuthStatusCallbacks_.erase(it);
        }
    }
    return ret;
}

int32_t CompanionDeviceAuthClientImpl::CheckLocalUserIdValid(int32_t userId, bool &isUserIdValid)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }
    int32_t ret = GENERAL_ERROR;
    int32_t ipcRet = proxy->CheckLocalUserIdValid(userId, isUserIdValid, ret);
    if (ipcRet != SUCCESS) {
        IAM_LOGE("ipc call return fail, ret:%{public}d", ipcRet);
        return GENERAL_ERROR;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("CheckLocalUserIdValid fail, ret:%{public}d", ret);
    }

    return ret;
}

sptr<ICompanionDeviceAuth> CompanionDeviceAuthClientImpl::GetProxy()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }

#ifdef ENABLE_TEST
    IAM_LOGE("proxy is nullptr in test mode, please use SetProxy() first");
    return proxy_;
#else
    // Use GetInstance() to avoid capturing [this]
    proxy_ = IpcClientFetcher::GetProxy([](const wptr<IRemoteObject> &remote) {
        auto &client = static_cast<CompanionDeviceAuthClient &>(CompanionDeviceAuthClient::GetInstance());
        auto &clientImpl = static_cast<CompanionDeviceAuthClientImpl &>(client);
        clientImpl.ResetProxy(remote);
    });

    return proxy_;
#endif // ENABLE_TEST
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

void CompanionDeviceAuthClientImpl::ReregisterDeviceSelectCallback()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (deviceSelectCallback_ == nullptr) {
        return;
    }
    RegisterDeviceSelectCallback(deviceSelectCallback_);
}

void CompanionDeviceAuthClientImpl::ResubscribeTemplateStatusChange()
{
    IAM_LOGI("start");
    std::vector<sptr<IpcTemplateStatusCallbackService>> callbacksCopy;
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        callbacksCopy = templateStatusCallbacks_;
        templateStatusCallbacks_ = {};
    }

    for (const auto &callback : callbacksCopy) {
        SubscribeTemplateStatusChangeInner(callback);
    }
}

void CompanionDeviceAuthClientImpl::ResubscribeContinuousAuthStatusChange()
{
    IAM_LOGI("start");
    std::vector<sptr<IpcContinuousAuthStatusCallbackService>> callbacksCopy;
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        callbacksCopy = continuousAuthStatusCallbacks_;
        continuousAuthStatusCallbacks_ = {};
    }
    for (const auto &callback : callbacksCopy) {
        SubscribeContinuousAuthStatusChangeInner(callback);
    }
}

void CompanionDeviceAuthClientImpl::ResubscribeAvailableDeviceStatus()
{
    IAM_LOGI("start");
    std::vector<sptr<IpcAvailableDeviceStatusCallbackService>> callbacksCopy;
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        callbacksCopy = availableDeviceStatusCallbacks_;
        availableDeviceStatusCallbacks_ = {};
    }
    for (const auto &callback : callbacksCopy) {
        SubscribeAvailableDeviceStatusInner(callback);
    }
}

void CompanionDeviceAuthClientImpl::SubscribeCompanionDeviceAuthSaStatus()
{
    IAM_LOGI("start");
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        if (companionDeviceAuthSaStatusListener_ != nullptr) {
            return;
        }
    }

    auto listener = SystemAbilityListener::Subscribe(
        "CompanionDeviceAuthService", SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH,
        [this]() {
            ReregisterDeviceSelectCallback();
            ResubscribeTemplateStatusChange();
            ResubscribeContinuousAuthStatusChange();
            ResubscribeAvailableDeviceStatus();
        },
        []() {});
    ScopeGuard unsubscribeGuard([&listener]() {
        if (listener != nullptr) {
            SystemAbilityListener::UnSubscribe(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, listener);
            listener = nullptr;
        }
    });
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        if (companionDeviceAuthSaStatusListener_ != nullptr) {
            return;
        }
        companionDeviceAuthSaStatusListener_ = listener;
        if (companionDeviceAuthSaStatusListener_ == nullptr) {
            IAM_LOGE("Subscribe CompanionDeviceAuthService fail");
            return;
        }
    }
    unsubscribeGuard.Cancel();
}

CompanionDeviceAuthClientImpl::~CompanionDeviceAuthClientImpl()
{
    IAM_LOGI("start");
    // Unsubscribe from system ability status changes to prevent callback from being invoked
    // after the client is destroyed
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (companionDeviceAuthSaStatusListener_ != nullptr) {
        SystemAbilityListener::UnSubscribe(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH,
            companionDeviceAuthSaStatusListener_);
        companionDeviceAuthSaStatusListener_ = nullptr;
    }
}

CompanionDeviceAuthClient &CompanionDeviceAuthClient::GetInstance()
{
    static CompanionDeviceAuthClientImpl impl;
    impl.SubscribeCompanionDeviceAuthSaStatus();
    return impl;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS