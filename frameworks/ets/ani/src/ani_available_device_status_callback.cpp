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

#include "ani_available_device_status_callback.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#include "common_defines.h"
#include "companion_device_auth_ani_helper.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH_ANI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
AniAvailableDeviceStatusCallback::AniAvailableDeviceStatusCallback()
{
}

AniAvailableDeviceStatusCallback::~AniAvailableDeviceStatusCallback()
{
}

void AniAvailableDeviceStatusCallback::OnAvailableDeviceStatusChange(
    const std::vector<ClientDeviceStatus> deviceStatusList)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    for (auto &callback : callbacks_) {
        DoCallback(deviceStatusList, callback);
    }
}

void AniAvailableDeviceStatusCallback::DoCallback(const std::vector<ClientDeviceStatus> deviceStatusList,
    AvailableDeviceStatusCallbackPtr callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return;
    }

    std::vector<companionDeviceAuth::DeviceStatus> temp;
    for (size_t i = 0; i < deviceStatusList.size(); ++i) {
        companionDeviceAuth::DeviceStatus deviceStatus =
            CompanionDeviceAuthAniHelper::ConvertDeviceStatus(deviceStatusList[i]);
        temp.push_back(deviceStatus);
    }
    taihe::array<companionDeviceAuth::DeviceStatus> result =
        taihe::array<companionDeviceAuth::DeviceStatus>(taihe::copy_data_t {}, temp.data(), temp.size());
    IAM_LOGI("start to execute callback");
    (**callback)(result);
    IAM_LOGI("execute callback success");
}

int32_t AniAvailableDeviceStatusCallback::SetCallback(taihe::optional<AvailableDeviceStatusCallback> callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (HasSameCallback(callback)) {
        IAM_LOGI("has same callback");
        return SUCCESS;
    }
    auto callbackPtr = MakeShared<taihe::optional<AvailableDeviceStatusCallback>>(callback);
    callbacks_.push_back(callbackPtr);
    IAM_LOGI("success");
    return SUCCESS;
}

void AniAvailableDeviceStatusCallback::ClearCallback()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    callbacks_.clear();
}

bool AniAvailableDeviceStatusCallback::HasCallback()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callbacks_.empty()) {
        return false;
    }
    return true;
}

bool AniAvailableDeviceStatusCallback::HasSameCallback(taihe::optional<AvailableDeviceStatusCallback> callback)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackPtr = MakeShared<taihe::optional<AvailableDeviceStatusCallback>>(callback);
    if (!HasCallback()) {
        return false;
    }
    if (!callbackPtr->has_value()) {
        return false;
    }
    auto callbackValue = callbackPtr->value();
    for (auto existCallback : callbacks_) {
        if (!existCallback->has_value()) {
            continue;
        }
        if (callbackValue == existCallback->value()) {
            IAM_LOGI("has same callback");
            return true;
        }
    }

    IAM_LOGI("do not have same callback");
    return false;
}

void AniAvailableDeviceStatusCallback::RemoveSingleCallback(taihe::optional<AvailableDeviceStatusCallback> callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackPtr = MakeShared<taihe::optional<AvailableDeviceStatusCallback>>(callback);
    if (!HasCallback()) {
        IAM_LOGE("callbacks_ is empty");
        return;
    }

    IAM_LOGI("begin to find the callback");
    if (!callbackPtr->has_value()) {
        return;
    }
    auto callbackValue = callbackPtr->value();
    bool findCallback = false;
    for (size_t i = 0; i < callbacks_.size(); ++i) {
        if (!callbacks_[i]->has_value()) {
            continue;
        }
        if (callbackValue == callbacks_[i]->value()) {
            IAM_LOGI("find the callback to remove");
            callbacks_.erase(callbacks_.begin() + i);
            findCallback = true;
            break;
        }
    }

    if (!findCallback) {
        IAM_LOGE("fail to find the callback to remove");
    } else {
        IAM_LOGI("remove success");
    }
}

int32_t AniAvailableDeviceStatusCallback::GetUserId()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return userId_;
}

void AniAvailableDeviceStatusCallback::SetUserId(int32_t userId)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    userId_ = userId;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS