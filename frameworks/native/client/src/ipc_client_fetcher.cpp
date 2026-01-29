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

#include "ipc_client_fetcher.h"

#include "iremote_broker.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "CDA_SDK"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

/**
 * @brief Internal DeathRecipient that wraps the user-provided callback
 */
class CompanionDeviceAuthDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit CompanionDeviceAuthDeathRecipient(const DeathCallback &callback) : callback_(callback)
    {
    }
    ~CompanionDeviceAuthDeathRecipient() override = default;

    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        if (callback_) {
            callback_(remote);
        }
    }

private:
    DeathCallback callback_;
};

sptr<ICompanionDeviceAuth> IpcClientFetcher::GetProxy(const DeathCallback &deathCallback)
{
    sptr<IRemoteObject> obj = GetRemoteObject();
    if (!obj) {
        IAM_LOGE("Failed to get remote object for CompanionDeviceAuth service");
        return nullptr;
    }

    sptr<IRemoteObject::DeathRecipient> dr = CreateDeathRecipient(deathCallback);
    if (!dr) {
        IAM_LOGE("Failed to create death recipient");
        return nullptr;
    }

    if (obj->IsProxyObject() && !obj->AddDeathRecipient(dr)) {
        IAM_LOGE("Failed to add death recipient");
        return nullptr;
    }

    sptr<ICompanionDeviceAuth> proxy = iface_cast<ICompanionDeviceAuth>(obj);
    if (!proxy) {
        IAM_LOGE("iface_cast failed for CompanionDeviceAuth service");
        if (obj->IsProxyObject()) {
            obj->RemoveDeathRecipient(dr);
        }
        return nullptr;
    }

    return proxy;
}

sptr<IRemoteObject> IpcClientFetcher::GetRemoteObject()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!sam) {
        IAM_LOGE("Failed to get system ability manager");
        return nullptr;
    }

    sptr<IRemoteObject> obj = sam->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH);
    if (!obj) {
        IAM_LOGE("Failed to get CompanionDeviceAuth service");
        return nullptr;
    }

    return obj;
}

sptr<IRemoteObject::DeathRecipient> IpcClientFetcher::CreateDeathRecipient(const DeathCallback &callback)
{
    auto recipient = new (std::nothrow) CompanionDeviceAuthDeathRecipient(callback);
    if (recipient == nullptr) {
        IAM_LOGE("Failed to create CompanionDeviceAuthDeathRecipient");
        return nullptr;
    }
    return recipient;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
