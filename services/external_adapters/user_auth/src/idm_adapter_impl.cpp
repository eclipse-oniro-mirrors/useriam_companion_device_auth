/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "idm_adapter_impl.h"

#include <cinttypes>
#include <new>
#include <set>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"

#include "user_idm_client.h"

#include "user_idm_client_defines.h"

#include "event_listener_callback_stub.h"
#include "iremote_object.h"
#include "sa_status_listener.h"
#include "system_ability_definition.h"
#include "task_runner_manager.h"
#include "user_auth_types.h"

#include "misc_manager.h"
#include "singleton_manager.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002510
#undef LOG_TAG
#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
using namespace UserAuth;

class CredChangeListener : public UserAuth::CredChangeEventListener {
public:
    explicit CredChangeListener(std::weak_ptr<IdmAdapterImpl> adapter) : adapter_(adapter)
    {
    }

    virtual ~CredChangeListener() = default;

    void OnNotifyCredChangeEvent(int32_t userId, UserAuth::AuthType authType, UserAuth::CredChangeEventType eventType,
        const UserAuth::CredChangeEventInfo &changeInfo) override
    {
        if (static_cast<UserAuth::AuthType>(authType) != UserAuth::AuthType::COMPANION_DEVICE) {
            return;
        }

        IAM_LOGI("OnNotifyCredChangeEvent: userId=%{public}d, eventType=%{public}d", userId, eventType);

        TaskRunnerManager::GetInstance().PostTaskOnResident([weakAdapter = adapter_, userId]() {
            auto adapter = weakAdapter.lock();
            ENSURE_OR_RETURN(adapter != nullptr);
            adapter->QueryAndUpdateCache(userId);
        });
    }

private:
    std::weak_ptr<IdmAdapterImpl> adapter_;
};

class TemplateChangeSubscription : public Subscription {
public:
    explicit TemplateChangeSubscription(std::function<void()> unsubscribe) : Subscription(std::move(unsubscribe))
    {
    }
};
} // namespace

IdmAdapterImpl::IdmAdapterImpl() = default;

IdmAdapterImpl::~IdmAdapterImpl()
{
}

bool IdmAdapterImpl::Initialize()
{
    eventListener_ = std::make_shared<CredChangeListener>(shared_from_this());
    ENSURE_OR_RETURN_VAL(eventListener_ != nullptr, false);
    IAM_LOGI("IdmAdapterImpl initialized");
    return true;
}

void IdmAdapterImpl::OnUserIdmServiceReady()
{
    IAM_LOGI("UserIdM SA is ready");

    ENSURE_OR_RETURN(eventListener_ != nullptr);

    std::vector<UserAuth::AuthType> authTypes = { UserAuth::AuthType::COMPANION_DEVICE };

    SetFirstCallerTokenID(IPCSkeleton::GetCallingTokenID());
    int32_t ret = UserIdmClient::GetInstance().RegistCredChangeEventListener(authTypes, eventListener_);
    SetFirstCallerTokenID(0);
    if (ret != ERR_OK) {
        IAM_LOGE("RegisterCredChangeEventListener failed: %{public}d", ret);
        return;
    }

    std::set<int32_t> subscribedUsers;
    for (const auto &[subscriptionId, userData] : subscriptions_) {
        subscribedUsers.insert(userData.first);
    }

    for (int32_t userId : subscribedUsers) {
        QueryAndUpdateCache(userId);
    }

    IAM_LOGI("UserIdM service ready, processed %{public}zu subscribed users", subscribedUsers.size());
}

void IdmAdapterImpl::OnUserIdmServiceUnavailable()
{
    IAM_LOGW("UserIdM SA is unavailable");

    if (eventListener_ != nullptr) {
        SetFirstCallerTokenID(IPCSkeleton::GetCallingTokenID());
        int32_t ret = UserIdmClient::GetInstance().UnRegistCredChangeEventListener(eventListener_);
        SetFirstCallerTokenID(0);
        if (ret != ERR_OK) {
            IAM_LOGW("UnRegistCredChangeEventListener failed: %{public}d", ret);
        }
    }
}

std::shared_ptr<IdmAdapterImpl> IdmAdapterImpl::Create()
{
    auto adapter = std::shared_ptr<IdmAdapterImpl>(new (std::nothrow) IdmAdapterImpl());
    if (adapter == nullptr) {
        IAM_LOGE("Failed to create IdmAdapterImpl");
        return nullptr;
    }

    if (!adapter->Initialize()) {
        IAM_LOGE("Failed to initialize IdmAdapterImpl");
        return nullptr;
    }

    return adapter;
}

std::vector<uint64_t> IdmAdapterImpl::GetUserTemplates(int32_t userId)
{
    auto it = templateCache_.find(userId);
    if (it == templateCache_.end()) {
        IAM_LOGI("No cached templates for user %{public}d, querying and update cache", userId);
        QueryAndUpdateCache(userId);
        it = templateCache_.find(userId);
    }

    if (it != templateCache_.end()) {
        return it->second;
    }

    IAM_LOGW("Still no templates found for user %{public}d after query", userId);
    return {};
}

std::unique_ptr<Subscription> IdmAdapterImpl::SubscribeUserTemplateChange(int32_t userId,
    TemplateChangeCallback callback)
{
    uint64_t subscriptionId = GetMiscManager().GetNextGlobalId();
    subscriptions_[subscriptionId] = { userId, std::move(callback) };

    IAM_LOGI("Subscribed to template changes for user %{public}d, subscriptionId=0x%{public}016" PRIX64, userId,
        subscriptionId);

    // Query initial template list
    QueryAndUpdateCache(userId);

    return std::make_unique<TemplateChangeSubscription>([weakThis = weak_from_this(), subscriptionId]() {
        auto self = weakThis.lock();
        if (self != nullptr) {
            self->Unsubscribe(subscriptionId);
        }
    });
}

void IdmAdapterImpl::Unsubscribe(uint64_t subscriptionId)
{
    auto it = subscriptions_.find(subscriptionId);
    if (it == subscriptions_.end()) {
        IAM_LOGW("Subscription 0x%{public}016" PRIX64 " not found", subscriptionId);
        return;
    }

    subscriptions_.erase(it);
    IAM_LOGI("Unsubscribe: subscriptionId=0x%{public}016" PRIX64 "", subscriptionId);
}

void IdmAdapterImpl::QueryAndUpdateCache(int32_t userId)
{
    std::vector<UserAuth::CredentialInfo> credentialInfoList;
    SetFirstCallerTokenID(IPCSkeleton::GetCallingTokenID());
    int32_t ret =
        UserIdmClient::GetInstance().GetCredentialInfoSync(userId, UserAuth::AuthType::ALL, credentialInfoList);
    SetFirstCallerTokenID(0);

    if (ret != ERR_OK) {
        IAM_LOGE("GetCredentialInfoSync failed for user %{public}d ret %{public}d", userId, ret);
        return;
    }

    std::vector<uint64_t> templateIds;
    for (const auto &credInfo : credentialInfoList) {
        templateIds.push_back(credInfo.templateId);
    }

    auto it = templateCache_.find(userId);
    if (it == templateCache_.end() || it->second != templateIds) {
        IAM_LOGI("Templates changed for user %{public}d, count: %{public}zu", userId, templateIds.size());
        NotifyTemplateChange(userId, templateIds);
    } else {
        IAM_LOGI("Templates unchanged for user %{public}d, count: %{public}zu", userId, templateIds.size());
    }
}

void IdmAdapterImpl::NotifyTemplateChange(int32_t userId, const std::vector<uint64_t> &templateIds)
{
    templateCache_[userId] = templateIds;

    std::vector<TemplateChangeCallback> callbacksToNotify;
    for (auto &[subscriptionId, userData] : subscriptions_) {
        auto &[subscribedUserId, callback] = userData;
        if (subscribedUserId == userId && callback) {
            callbacksToNotify.push_back(callback);
        }
    }

    if (callbacksToNotify.empty()) {
        return;
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [callbacks = std::move(callbacksToNotify), userId, templateIds]() {
            for (auto &callback : callbacks) {
                callback(userId, templateIds);
            }
        });

    IAM_LOGI("Notified %{public}zu subscribers for user %{public}d", callbacksToNotify.size(), userId);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
