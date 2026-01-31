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

#ifndef COMPANION_DEVICE_AUTH_FRAMEWORK_CALLBACK_HOLDER_H
#define COMPANION_DEVICE_AUTH_FRAMEWORK_CALLBACK_HOLDER_H

#include "iam_logger.h"
#include "common_defines.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "CDA_FRAMEWORK"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
template <typename T>
class CallbackHolder {
public:
    CallbackHolder() = default;
    virtual ~CallbackHolder() = default;

    int32_t AddCallback(const std::shared_ptr<T> &callback, std::function<int()> func)
    {
        IAM_LOGI("start");
        if (callback == nullptr || func == nullptr) {
            IAM_LOGE("invalid param");
            return GENERAL_ERROR;
        }

        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
            [callback](const std::shared_ptr<T> &item) {
                if (callback == nullptr || item == nullptr) {
                    return false;
                }
                return *callback == *item;
            });
        if (it != callbacks_.end()) {
            IAM_LOGI("callback already exists");
            return SUCCESS;
        }

        if (!callbacks_.empty()) {
            IAM_LOGI("callback already registered, add only");
            callbacks_.push_back(callback);
            return SUCCESS;
        }

        callbacks_.push_back(callback);
        int32_t ret = func();
        if (ret != SUCCESS) {
            IAM_LOGE("call func fail:%{public}d", ret);
            callbacks_.pop_back();
            return ret;
        }

        IAM_LOGI("callback registered success");
        return SUCCESS;
    }

    int32_t RemoveCallback(const std::shared_ptr<T> &callback, std::function<int()> func)
    {
        IAM_LOGI("start");
        if (func == nullptr) {
            IAM_LOGE("invalid param");
            return GENERAL_ERROR;
        }

        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (callback == nullptr) {
            if (callbacks_.empty()) {
                IAM_LOGI("no callback to remove");
                return SUCCESS;
            }
            int32_t ret = func();
            if (ret != SUCCESS) {
                IAM_LOGE("call func fail:%{public}d", ret);
                return ret;
            }
            callbacks_.clear();
            return SUCCESS;
        }

        auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
            [callback](const std::shared_ptr<T> &item) {
                if (callback == nullptr || item == nullptr) {
                    return false;
                }
                return *callback == *item;
            });
        if (it == callbacks_.end()) {
            IAM_LOGI("callback not found");
            return GENERAL_ERROR;
        }

        if (callbacks_.size() == 1) {
            int32_t ret = func();
            if (ret != SUCCESS) {
                IAM_LOGE("call func fail:%{public}d", ret);
                return ret;
            }
        }
        callbacks_.erase(it);
        return SUCCESS;
    }

    std::vector<std::shared_ptr<T>> GetCallbacks() const
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return callbacks_;
    }

    bool Empty() const
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return callbacks_.empty();
    }

private:
    mutable std::recursive_mutex mutex_;
    std::vector<std::shared_ptr<T>> callbacks_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // COMPANION_DEVICE_AUTH_FRAMEWORK_CALLBACK_HOLDER_H