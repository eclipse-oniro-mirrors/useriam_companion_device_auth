/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef STATUS_MONITOR_H
#define STATUS_MONITOR_H

#include <unordered_map>
#include <vector>

#include "iam_logger.h"

#include "common_defines.h"
#include "companion_device_auth_client.h"
#include "available_device_status_callback_holder.h"
#include "continuous_auth_status_callback_holder.h"
#include "template_status_callback_holder.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "CDA_FRAMEWORK"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
template <typename T, typename A, typename C>
class StatusMonitor {
public:
    static int32_t CheckUserId(int32_t userId)
    {
        bool isUserIdValid = false;
        int32_t ret = CompanionDeviceAuthClient::GetInstance().CheckLocalUserIdValid(userId, isUserIdValid);
        if (ret != SUCCESS) {
            IAM_LOGE("CheckLocalUserIdValid fail, ret:%{public}d", ret);
            return GENERAL_ERROR;
        }
        if (!isUserIdValid) {
            IAM_LOGE("input local user id is invalid");
            return USER_ID_NOT_FOUND;
        }
        return SUCCESS;
    }

    explicit StatusMonitor(int32_t userId)
        : userId_(userId),
          templateStatusCallbackHodler_(std::make_shared<TemplateStatusCallbackHolder<T>>()),
          availableDeviceStatusCallbackHodler_(std::make_shared<AvailableDeviceStatusCallbackHolder<A>>()) {}
    ~StatusMonitor() = default;

    int32_t GetTemplateStatus(std::vector<ClientTemplateStatus> &clientTemplateStatusList)
    {
        IAM_LOGI("start");
        int32_t ret = CompanionDeviceAuthClient::GetInstance().GetTemplateStatus(userId_, clientTemplateStatusList);
        if (ret != SUCCESS) {
            IAM_LOGE("GetTemplateStatus fail, ret:%{public}d", ret);
            return ret;
        }
        IAM_LOGI("success");
        return SUCCESS;
    }

    int32_t OnTemplateChange(const std::shared_ptr<TemplateStatusCallbackWrapper<T>> &callback)
    {
        IAM_LOGI("start");
        return templateStatusCallbackHodler_->AddCallback(
            callback,
            [this]() {
                int32_t ret = CompanionDeviceAuthClient::GetInstance()
                    .SubscribeTemplateStatusChange(userId_, templateStatusCallbackHodler_);
                if (ret != SUCCESS) {
                    IAM_LOGE("SubscribeTemplateStatusChange fail, ret:%{public}d", ret);
                }
                return ret;
            }
        );
    }

    int32_t OffTemplateChange(const std::shared_ptr<TemplateStatusCallbackWrapper<T>> &callback)
    {
        IAM_LOGI("start");
        return templateStatusCallbackHodler_->RemoveCallback(
            callback,
            [this]() {
                int32_t ret = CompanionDeviceAuthClient::GetInstance()
                    .UnsubscribeTemplateStatusChange(templateStatusCallbackHodler_);
                if (ret != SUCCESS) {
                    IAM_LOGE("UnsubscribeAvailableDeviceStatus fail, ret:%{public}d", ret);
                }
                return ret;
            }
        );
    }

    int32_t OnAvailableDeviceChange(const std::shared_ptr<AvailableDeviceStatusCallbackWrapper<A>> &callback)
    {
        IAM_LOGI("start");
        return availableDeviceStatusCallbackHodler_->AddCallback(
            callback,
            [this]() {
                int32_t ret = CompanionDeviceAuthClient::GetInstance()
                    .SubscribeAvailableDeviceStatus(userId_, availableDeviceStatusCallbackHodler_);
                if (ret != SUCCESS) {
                    IAM_LOGE("SubscribeAvailableDeviceStatus fail, ret:%{public}d", ret);
                }
                return ret;
            }
        );
    }

    int32_t OffAvailableDeviceChange(const std::shared_ptr<AvailableDeviceStatusCallbackWrapper<A>> &callback)
    {
        IAM_LOGI("start");
        return availableDeviceStatusCallbackHodler_->RemoveCallback(
            callback,
            [this]() {
                int32_t ret = CompanionDeviceAuthClient::GetInstance()
                    .UnsubscribeAvailableDeviceStatus(availableDeviceStatusCallbackHodler_);
                if (ret != SUCCESS) {
                    IAM_LOGE("UnsubscribeAvailableDeviceStatus fail, ret:%{public}d", ret);
                }
                return ret;
            }
        );
    }

    int32_t OnContinuousAuthChange(
        std::optional<uint64_t> templateId, const std::shared_ptr<ContinuousAuthStatusCallbackWrapper<C>> &callback)
    {
        IAM_LOGI("start");
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = continuousAuthStatusCallbackMap_.find(templateId);
        std::shared_ptr<ContinuousAuthStatusCallbackHolder<C>> callbackHolder = nullptr;
        if (it == continuousAuthStatusCallbackMap_.end()) {
            callbackHolder = std::make_shared<ContinuousAuthStatusCallbackHolder<C>>();
        } else {
            callbackHolder = it->second;
        }
        if (callbackHolder == nullptr) {
            IAM_LOGE("callbackHolder is nullptr");
            return GENERAL_ERROR;
        }

        int32_t result = callbackHolder->AddCallback(
            callback,
            [this, templateId, &callbackHolder]() {
                int32_t ret = CompanionDeviceAuthClient::GetInstance()
                    .SubscribeContinuousAuthStatusChange(userId_, templateId, callbackHolder);
                if (ret != SUCCESS) {
                    IAM_LOGE("SubscribeContinuousAuthStatusChange fail, ret:%{public}d", ret);
                }
                return ret;
            }
        );
        if (result == SUCCESS) {
            continuousAuthStatusCallbackMap_[templateId] = callbackHolder;
        }
        return result;
    }

    int32_t OffContinuousAuthChange(const std::shared_ptr<ContinuousAuthStatusCallbackWrapper<C>> &callback)
    {
        IAM_LOGI("start");
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        int32_t ret = GENERAL_ERROR;
        for (auto it = continuousAuthStatusCallbackMap_.begin(); it != continuousAuthStatusCallbackMap_.end();) {
            if (it->second == nullptr) {
                it = continuousAuthStatusCallbackMap_.erase(it);
                continue;
            }
            ret = it->second->RemoveCallback(callback,
                [this, &it]() {
                    int32_t ret = CompanionDeviceAuthClient::GetInstance()
                        .UnsubscribeContinuousAuthStatusChange(it->second);
                    if (ret != SUCCESS) {
                        IAM_LOGE("UnsubscribeContinuousAuthStatusChange fail, ret:%{public}d", ret);
                    }
                    return ret;
                });
            if (ret != SUCCESS) {
                IAM_LOGE("RemoveCallback fail, ret:%{public}d", ret);
                return ret;
            }
            if (it->second->Empty()) {
                it = continuousAuthStatusCallbackMap_.erase(it);
                continue;
            }
            ++it;
        }
        if (ret != SUCCESS) {
            IAM_LOGE("no same callback registered yet");
        }
        return ret;
    }

private:
    mutable std::recursive_mutex mutex_;
    int32_t userId_;
    std::shared_ptr<TemplateStatusCallbackHolder<T>> templateStatusCallbackHodler_;
    std::shared_ptr<AvailableDeviceStatusCallbackHolder<A>> availableDeviceStatusCallbackHodler_;
    std::unordered_map<std::optional<uint64_t>, std::shared_ptr<ContinuousAuthStatusCallbackHolder<C>>>
        continuousAuthStatusCallbackMap_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // STATUS_MONITOR_H