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

#include "adapter_manager.h"
#include "iam_check.h"
#include "iam_logger.h"

#include "parameter.h"
#include "singleton_manager.h"
#include "subscription.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_SYSTEM_PARAM_MANAGER_IMPL

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
void OnParamChg(const char *key, const char *value, void *context)
{
    ENSURE_OR_RETURN(key != nullptr);
    ENSURE_OR_RETURN(value != nullptr);
    (void)context;

    TaskRunnerManager::GetInstance().PostTaskOnResident([key = std::string(key), value = std::string(value)]() {
        auto &manager = AdapterManager::GetInstance().GetSystemParamManager();
        manager.OnParamChange(key, value);
    });
}
} // namespace

std::shared_ptr<SystemParamManagerImpl> SystemParamManagerImpl::Create()
{
    auto manager = std::shared_ptr<SystemParamManagerImpl>(new (std::nothrow) SystemParamManagerImpl());
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
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
    // clang-format off
    bool isFirstSubscriptionForKey = std::find_if(subscriptions_.begin(), subscriptions_.end(),
        [&key](const auto &info) { return info.key == key; }) == subscriptions_.end();
    // clang-format on
    if (isFirstSubscriptionForKey) {
        int32_t ret = WatchParameter(key.c_str(), OnParamChg, nullptr);
        if (ret != 0) {
            IAM_LOGE("WatchParameter failed, key %{public}s, ret %{public}d", key.c_str(), ret);
            return nullptr;
        }
    }

    subscriptions_.push_back({ subscriptionId, key, std::move(callback) });

    IAM_LOGD("watch key %{public}s, subscription id 0x%{public}016" PRIX64, key.c_str(), subscriptionId);

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnwatchParam(subscriptionId);
        IAM_LOGD("system param subscription removed: 0x%{public}016" PRIX64 "", subscriptionId);
    });
}

void SystemParamManagerImpl::UnwatchParam(SubscribeId subscriptionId)
{
    auto it = std::find_if(subscriptions_.begin(), subscriptions_.end(),
        [subscriptionId](const auto &info) { return info.id == subscriptionId; });
    if (it == subscriptions_.end()) {
        return;
    }

    std::string key = it->key;
    subscriptions_.erase(it);

    // clang-format off
    bool hasOtherSubscriptionForKey = std::find_if(subscriptions_.begin(), subscriptions_.end(),
        [&key](const auto &info) { return info.key == key; }) != subscriptions_.end();
    // clang-format on
    if (!hasOtherSubscriptionForKey) {
        int32_t ret = RemoveParameterWatcher(key.c_str(), OnParamChg, nullptr);
        if (ret != 0) {
            IAM_LOGE("RemoveParameterWatcher failed, key %{public}s, ret %{public}d", key.c_str(), ret);
        }
    }

    IAM_LOGD("unwatch subscription id 0x%{public}016" PRIX64 ", key %{public}s", subscriptionId, key.c_str());
}

void SystemParamManagerImpl::OnParamChange(const std::string &key, const std::string &value)
{
    IAM_LOGI("on param change, key %{public}s, value %{public}s", key.c_str(), value.c_str());
    std::vector<SystemParamCallback> callbacks;
    for (const auto &info : subscriptions_) {
        if (info.key == key && info.callback != nullptr) {
            callbacks.push_back(info.callback);
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
