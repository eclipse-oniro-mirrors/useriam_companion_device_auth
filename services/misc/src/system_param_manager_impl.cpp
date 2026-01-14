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

#include "system_param_manager_impl.h"

#include <algorithm>
#include <cinttypes>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "parameter.h"
#include "singleton_manager.h"
#include "subscription.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
void OnParamChg(const char *key, const char *value, void *context)
{
    ENSURE_OR_RETURN(key != nullptr);
    ENSURE_OR_RETURN(value != nullptr);
    ENSURE_OR_RETURN(context != nullptr);
    auto *manager = static_cast<SystemParamManagerImpl *>(context);
    manager->OnParamChange(std::string(key), std::string(value));
}
} // namespace

std::shared_ptr<SystemParamManagerImpl> SystemParamManagerImpl::Create()
{
    auto manager = std::shared_ptr<SystemParamManagerImpl>(new (std::nothrow) SystemParamManagerImpl());
    if (manager == nullptr) {
        IAM_LOGE("failed to create SystemParamManagerImpl");
        return nullptr;
    }
    return manager;
}

SystemParamManagerImpl::SystemParamManagerImpl()
{
}

std::string SystemParamManagerImpl::GetParam(const std::string &key, const std::string &defaultValue)
{
    constexpr uint32_t MAX_VALUE_LEN = 128;
    char valueBuffer[MAX_VALUE_LEN] = { 0 };
    int32_t ret = GetParameter(key.c_str(), defaultValue.c_str(), valueBuffer, MAX_VALUE_LEN);
    if (ret < 0) {
        IAM_LOGE("get param failed, key %{public}s, ret %{public}d, use default value %{public}s", key.c_str(), ret,
            defaultValue.c_str());
        return defaultValue;
    }
    IAM_LOGI("get param key %{public}s value %{public}s", key.c_str(), valueBuffer);
    return std::string(valueBuffer);
}

void SystemParamManagerImpl::SetParam(const std::string &key, const std::string &value)
{
    std::string currentValue = GetParam(key, "");
    IAM_LOGI("set parameter: %{public}s, current value: %{public}s, value: %{public}s", key.c_str(),
        currentValue.c_str(), value.c_str());
    if (currentValue != value) {
        int32_t ret = SetParameter(key.c_str(), value.c_str());
        ENSURE_OR_RETURN(ret == 0);
    }
}

void SystemParamManagerImpl::SetParamTwice(const std::string &key, const std::string &value1, const std::string &value2)
{
    std::string currentValue = GetParam(key, "");
    IAM_LOGI("set parameter: %{public}s, current value: %{public}s, value1: %{public}s, value2: %{public}s",
        key.c_str(), currentValue.c_str(), value1.c_str(), value2.c_str());
    if (currentValue != value1) {
        int32_t ret1 = SetParameter(key.c_str(), value1.c_str());
        ENSURE_OR_RETURN(ret1 == 0);
    }
    int32_t ret2 = SetParameter(key.c_str(), value2.c_str());
    ENSURE_OR_RETURN(ret2 == 0);
}

std::unique_ptr<Subscription> SystemParamManagerImpl::WatchParam(const std::string &key, SystemParamCallback &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    bool isFirstSubscriptionForKey = false;

    isFirstSubscriptionForKey = keyToSubscriptionIds_.find(key) == keyToSubscriptionIds_.end();
    if (isFirstSubscriptionForKey) {
        int32_t ret = WatchParameter(key.c_str(), OnParamChg, this);
        if (ret != 0) {
            IAM_LOGE("WatchParameter failed, key %{public}s, ret %{public}d", key.c_str(), ret);
            return nullptr;
        }
    }

    subscriptions_[subscriptionId] = std::move(callback);
    keyToSubscriptionIds_[key].push_back(subscriptionId);

    IAM_LOGI("watch key %{public}s, subscription id %{public}" PRIu64, key.c_str(), subscriptionId);

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnwatchParam(subscriptionId);
        IAM_LOGI("system param subscription removed: %{public}" PRIu64, subscriptionId);
    });
}

void SystemParamManagerImpl::UnwatchParam(SubscribeId subscriptionId)
{
    auto subscriptionIt = subscriptions_.find(subscriptionId);
    if (subscriptionIt == subscriptions_.end()) {
        return;
    }

    std::string keyToRemove;
    for (auto it = keyToSubscriptionIds_.begin(); it != keyToSubscriptionIds_.end(); ++it) {
        auto &subscriptionIds = it->second;
        auto subscriptionIdIt = std::find(subscriptionIds.begin(), subscriptionIds.end(), subscriptionId);
        if (subscriptionIdIt != subscriptionIds.end()) {
            keyToRemove = it->first;
            subscriptionIds.erase(subscriptionIdIt);
            if (subscriptionIds.empty()) {
                keyToRemove = it->first;
            }
            break;
        }
    }

    if (!keyToRemove.empty() && keyToSubscriptionIds_[keyToRemove].empty()) {
        keyToSubscriptionIds_.erase(keyToRemove);
    }

    subscriptions_.erase(subscriptionIt);
    IAM_LOGI("unwatch subscription id %{public}" PRIu64 ", key %{public}s", subscriptionId, keyToRemove.c_str());
}

void SystemParamManagerImpl::OnParamChange(const std::string &key, const std::string &value)
{
    IAM_LOGI("on param change, key %{public}s, value %{public}s", key.c_str(), value.c_str());
    std::vector<SystemParamCallback> callbacks;
    auto keyIt = keyToSubscriptionIds_.find(key);
    if (keyIt != keyToSubscriptionIds_.end()) {
        callbacks.reserve(keyIt->second.size());
        for (SubscribeId subscriptionId : keyIt->second) {
            auto subscriptionIt = subscriptions_.find(subscriptionId);
            if (subscriptionIt != subscriptions_.end() && subscriptionIt->second != nullptr) {
                callbacks.push_back(subscriptionIt->second);
            }
        }
    }

    if (callbacks.empty()) {
        return;
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident([callbacks = std::move(callbacks), value]() {
        for (const auto &callback : callbacks) {
            if (callback != nullptr) {
                callback(value);
            }
        }
    });
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
