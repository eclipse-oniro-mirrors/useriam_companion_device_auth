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

#include "ani_template_status_callback.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "common_defines.h"
#include "companion_device_auth_ani_helper.h"
#include "ohos.userIAM.companionDeviceAuth.proj.hpp"
#include "scope_guard.h"

#define LOG_TAG "CDA_ANI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
AniTemplateStatusCallback::AniTemplateStatusCallback()
{
    env_ = ::taihe::get_env();
    if (env_ == nullptr) {
        IAM_LOGE("get null env");
        return;
    }
    IAM_LOGI("env is not null");
    env_->GetVM(&vm_);
}

AniTemplateStatusCallback::~AniTemplateStatusCallback()
{
}

void AniTemplateStatusCallback::OnTemplateStatusChange(const std::vector<ClientTemplateStatus> templateStatusList)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    for (auto &callback : callbacks_) {
        DoCallback(templateStatusList, callback);
    }
}

void AniTemplateStatusCallback::DoCallback(const std::vector<ClientTemplateStatus> templateStatusList,
    TemplateStatusCallbackPtr callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return;
    }

    std::vector<companionDeviceAuth::TemplateStatus> temp;
    ani_env *env = nullptr;
    ani_options aniArgs { 0, nullptr };
    if (vm_ == nullptr) {
        IAM_LOGE("vm_ is null");
        return;
    }
    auto status = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        IAM_LOGE("get ani env fail");
        return;
    }

    ScopeGuard detachGuard([vm = vm_]() { vm->DetachCurrentThread(); });

    for (size_t i = 0; i < templateStatusList.size(); ++i) {
        companionDeviceAuth::TemplateStatus templateStatus =
            CompanionDeviceAuthAniHelper::ConvertTemplateStatus(templateStatusList[i], env);
        temp.push_back(templateStatus);
    }
    taihe::array<companionDeviceAuth::TemplateStatus> result =
        taihe::array<companionDeviceAuth::TemplateStatus>(taihe::copy_data_t {}, temp.data(), temp.size());
    (**callback)(result);
    IAM_LOGI("success");
}

int32_t AniTemplateStatusCallback::SetCallback(taihe::optional<TemplateStatusCallback> callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (HasSameCallback(callback)) {
        IAM_LOGI("has same callback");
        return SUCCESS;
    }
    auto callbackPtr = std::make_shared<taihe::optional<TemplateStatusCallback>>(callback);
    ENSURE_OR_RETURN_VAL(callbackPtr != nullptr, GENERAL_ERROR);
    callbacks_.push_back(callbackPtr);
    IAM_LOGI("success");
    return SUCCESS;
}

void AniTemplateStatusCallback::ClearCallback()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    callbacks_.clear();
}

bool AniTemplateStatusCallback::HasCallback()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callbacks_.empty()) {
        return false;
    }
    return true;
}

bool AniTemplateStatusCallback::HasSameCallback(taihe::optional<TemplateStatusCallback> callback)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackPtr = std::make_shared<taihe::optional<TemplateStatusCallback>>(callback);
    ENSURE_OR_RETURN_VAL(callbackPtr != nullptr, false);
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

void AniTemplateStatusCallback::RemoveSingleCallback(taihe::optional<TemplateStatusCallback> callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackPtr = std::make_shared<taihe::optional<TemplateStatusCallback>>(callback);
    ENSURE_OR_RETURN(callbackPtr != nullptr);
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

int32_t AniTemplateStatusCallback::GetUserId()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return userId_;
}

void AniTemplateStatusCallback::SetUserId(int32_t userId)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    userId_ = userId;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS