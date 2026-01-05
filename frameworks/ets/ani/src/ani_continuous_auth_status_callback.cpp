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

#include "ani_continuous_auth_status_callback.h"

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
AniContinuousAuthStatusCallback::AniContinuousAuthStatusCallback()
{
}

AniContinuousAuthStatusCallback::~AniContinuousAuthStatusCallback()
{
}

void AniContinuousAuthStatusCallback::OnContinuousAuthStatusChange(const bool isAuthPassed,
    const std::optional<int32_t> authTrustLevel)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    for (auto &callback : callbacks_) {
        DoCallback(callback, isAuthPassed, authTrustLevel);
    }
}

void AniContinuousAuthStatusCallback::DoCallback(ContinuousAuthStatusCallbackPtr callback, const bool isAuthPassed,
    const std::optional<int32_t> authTrustLevel)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return;
    }

    if (authTrustLevel.has_value()) {
        if (!CompanionDeviceAuthAniHelper::IsAuthTrustLevelValid(authTrustLevel.value())) {
            IAM_LOGE("invalid atl");
            return;
        }
        ::ohos::userIAM::userAuth::userAuth::AuthTrustLevel aniAuthTrustLevel =
            CompanionDeviceAuthAniHelper::ConvertAuthTrustLevel(authTrustLevel.value());
        ::taihe::optional<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> optAuthTrustLevel(std::in_place,
            aniAuthTrustLevel);
        (**callback)(isAuthPassed, optAuthTrustLevel);
        return;
    }

    (**callback)(isAuthPassed,
        ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> { std::nullopt });
}

int32_t AniContinuousAuthStatusCallback::SetCallback(taihe::optional<ContinuousAuthStatusCallback> callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (HasSameCallback(callback)) {
        IAM_LOGI("has same callback");
        return SUCCESS;
    }
    auto callbackPtr = MakeShared<taihe::optional<ContinuousAuthStatusCallback>>(callback);
    callbacks_.push_back(callbackPtr);
    IAM_LOGI("success");
    return SUCCESS;
}

void AniContinuousAuthStatusCallback::ClearCallback()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    callbacks_.clear();
}

bool AniContinuousAuthStatusCallback::HasCallback()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callbacks_.empty()) {
        return false;
    }
    return true;
}

void AniContinuousAuthStatusCallback::RemoveSingleCallback(taihe::optional<ContinuousAuthStatusCallback> callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackPtr = MakeShared<taihe::optional<ContinuousAuthStatusCallback>>(callback);
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

bool AniContinuousAuthStatusCallback::HasSameCallback(taihe::optional<ContinuousAuthStatusCallback> callback)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackPtr = MakeShared<taihe::optional<ContinuousAuthStatusCallback>>(callback);
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

int32_t AniContinuousAuthStatusCallback::GetUserId()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return userId_;
}

void AniContinuousAuthStatusCallback::SetUserId(int32_t userId)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    userId_ = userId;
}

std::optional<uint64_t> AniContinuousAuthStatusCallback::GetTemplateId()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return templateId_;
}

void AniContinuousAuthStatusCallback::SetTemplateId(uint64_t templateId)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    templateId_ = templateId;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS