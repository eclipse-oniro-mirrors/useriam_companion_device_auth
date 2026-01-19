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

#include "status_monitor.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#include "companion_device_auth_ani_helper.h"

#define LOG_TAG "CDA_ANI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
StatusMonitor::StatusMonitor(int32_t localUserId)
    : availableDeviceStatusCallback_(MakeShared<AniAvailableDeviceStatusCallback>()),
      templateStatusCallback_(MakeShared<AniTemplateStatusCallback>())
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (availableDeviceStatusCallback_ == nullptr) {
        IAM_LOGE("get null availableDeviceStatusCallback_");
    }

    if (templateStatusCallback_ == nullptr) {
        IAM_LOGE("get null templateStatusCallback_");
    }
    localUserId_ = localUserId;
    availableDeviceStatusCallback_->SetUserId(localUserId);
    templateStatusCallback_->SetUserId(localUserId);
}

int32_t StatusMonitor::GetTemplateStatus(std::vector<ClientTemplateStatus> &clientTemplateStatusList)
{
    IAM_LOGI("start");
    int32_t ret = CompanionDeviceAuthClient::GetInstance().GetTemplateStatus(localUserId_, clientTemplateStatusList);
    if (ret != SUCCESS) {
        IAM_LOGE("GetTemplateStatus fail");
        return ret;
    }
    return SUCCESS;
}

int32_t StatusMonitor::OnTemplateChange(::taihe::callback_view<void(
        ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>
        callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (templateStatusCallback_ == nullptr) {
        IAM_LOGE("templateStatusCallback_ is null");
        return GENERAL_ERROR;
    }

    if (!templateStatusCallback_->HasCallback()) {
        int32_t ret = templateStatusCallback_->SetCallback(::taihe::optional<::taihe::callback<void(
                ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>> {
            std::in_place_t {}, callback });
        IAM_LOGI("lihuayue SubscribeTemplateStatusChange");
        ret = CompanionDeviceAuthClient::GetInstance().SubscribeTemplateStatusChange(localUserId_,
            templateStatusCallback_);
        if (ret != SUCCESS) {
            IAM_LOGE("SubscribeTemplateStatusChange fail");
            templateStatusCallback_->ClearCallback();
            return ret;
        }
        return SUCCESS;
    }

    IAM_LOGI("lihuayue do not need to subscribe");
    return templateStatusCallback_->SetCallback(::taihe::optional<::taihe::callback<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>> {
        std::in_place_t {}, callback });
}

int32_t StatusMonitor::OffTemplateChange(::taihe::optional_view<::taihe::callback<void(
        ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>>
        callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (templateStatusCallback_ == nullptr) {
        IAM_LOGE("templateStatusCallback_ is null");
        return GENERAL_ERROR;
    }

    if (!callback.has_value()) {
        int32_t ret = CompanionDeviceAuthClient::GetInstance().UnsubscribeTemplateStatusChange(templateStatusCallback_);
        if (ret != SUCCESS) {
            IAM_LOGE("UnsubscribeAvailableDeviceStatus fail");
            return ret;
        }
        templateStatusCallback_->ClearCallback();
        return SUCCESS;
    }

    templateStatusCallback_->RemoveSingleCallback(::taihe::optional<::taihe::callback<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>> {
        std::in_place_t {}, callback.value() });
    return SUCCESS;
}

int32_t StatusMonitor::OnAvailableDeviceChange(::taihe::callback_view<void(
        ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>
        callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (availableDeviceStatusCallback_ == nullptr) {
        IAM_LOGE("availableDeviceStatusCallback_ is null");
        return GENERAL_ERROR;
    }

    if (!availableDeviceStatusCallback_->HasCallback()) {
        int32_t ret = availableDeviceStatusCallback_->SetCallback(::taihe::optional<::taihe::callback<void(
                ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>> {
            std::in_place_t {}, callback });
        IAM_LOGI("lihuayue SubscribeAvailableDeviceStatus");
        ret = CompanionDeviceAuthClient::GetInstance().SubscribeAvailableDeviceStatus(localUserId_,
            availableDeviceStatusCallback_);
        if (ret != SUCCESS) {
            IAM_LOGE("SubscribeAvailableDeviceStatus fail");
            availableDeviceStatusCallback_->ClearCallback();
            return ret;
        }
        return SUCCESS;
    }

    IAM_LOGI("lihuayue do not need to subscribe");
    return availableDeviceStatusCallback_->SetCallback(::taihe::optional<::taihe::callback<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>> {
        std::in_place_t {}, callback });
}

int32_t StatusMonitor::OffAvailableDeviceChange(::taihe::optional_view<
    ::taihe::callback<void(::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>>
        callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (availableDeviceStatusCallback_ == nullptr) {
        IAM_LOGE("availableDeviceStatusCallback_ is null");
        return GENERAL_ERROR;
    }

    if (!callback.has_value()) {
        int32_t ret =
            CompanionDeviceAuthClient::GetInstance().UnsubscribeAvailableDeviceStatus(availableDeviceStatusCallback_);
        if (ret != SUCCESS) {
            IAM_LOGE("UnsubscribeAvailableDeviceStatus fail");
            return ret;
        }
        availableDeviceStatusCallback_->ClearCallback();
        return SUCCESS;
    }

    availableDeviceStatusCallback_->RemoveSingleCallback(::taihe::optional<::taihe::callback<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>> {
        std::in_place_t {}, callback.value() });
    return SUCCESS;
}

int32_t StatusMonitor::OnContinuousAuthChange(companionDeviceAuth::ContinuousAuthParam const &param,
    ::taihe::callback_view<void(bool isAuthPassed,
        ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>
        callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    int32_t ret = UpdateContinuousAuthStatusCallback(param, callback);
    if (ret == SUCCESS) {
        IAM_LOGI("UpdateContinuousAuthStatusCallback success");
        return ret;
    }

    if (param.templateId.has_value()) {
        uint64_t templateId = CompanionDeviceAuthAniHelper::ConvertAniTemplateId(param.templateId.value());
        auto continuousAuthStatusCallback = MakeShared<AniContinuousAuthStatusCallback>();
        continuousAuthStatusCallback->SetTemplateId(templateId);
        continuousAuthStatusCallback->SetCallback(::taihe::optional<::taihe::callback<void(bool isAuthPassed,
                ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>> {
            std::in_place_t {}, callback });
        continuousAuthStatusCallbacks_.push_back(continuousAuthStatusCallback);
        ret = CompanionDeviceAuthClient::GetInstance().SubscribeContinuousAuthStatusChange(localUserId_,
            continuousAuthStatusCallback, templateId);
        if (ret != SUCCESS) {
            IAM_LOGE("SubscribeContinuousAuthStatusChange fail");
            continuousAuthStatusCallback->ClearCallback();
            continuousAuthStatusCallbacks_.pop_back();
            return ret;
        }
    } else {
        auto continuousAuthStatusCallback = MakeShared<AniContinuousAuthStatusCallback>();
        continuousAuthStatusCallback->SetCallback(::taihe::optional<::taihe::callback<void(bool isAuthPassed,
                ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>> {
            std::in_place_t {}, callback });
        continuousAuthStatusCallbacks_.push_back(continuousAuthStatusCallback);
        ret = CompanionDeviceAuthClient::GetInstance().SubscribeContinuousAuthStatusChange(localUserId_,
            continuousAuthStatusCallback);
        if (ret != SUCCESS) {
            IAM_LOGE("SubscribeContinuousAuthStatusChange fail");
            continuousAuthStatusCallback->ClearCallback();
            continuousAuthStatusCallbacks_.pop_back();
            return ret;
        }
    }
    return SUCCESS;
}

int32_t StatusMonitor::UpdateContinuousAuthStatusCallback(companionDeviceAuth::ContinuousAuthParam const &param,
    ::taihe::callback_view<void(bool isAuthPassed,
        ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>
        callback)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    bool hasSameCallback = false;
    int32_t ret;
    if (!param.templateId.has_value()) {
        for (auto &continuousAuthStatusCallback : continuousAuthStatusCallbacks_) {
            if (continuousAuthStatusCallback->GetTemplateId().has_value()) {
                continue;
            }
            ret = continuousAuthStatusCallback->SetCallback(::taihe::optional<::taihe::callback<void(bool isAuthPassed,
                    ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>> {
                std::in_place_t {}, callback });
            if (ret != SUCCESS) {
                IAM_LOGE("SetCallback fail, ret:%{public}d", ret);
                return ret;
            }
            hasSameCallback = true;
        }
    } else {
        uint64_t templateId = CompanionDeviceAuthAniHelper::ConvertAniTemplateId(param.templateId.value());
        uint64_t callbackTemplateId;
        for (auto &continuousAuthStatusCallback : continuousAuthStatusCallbacks_) {
            if (!continuousAuthStatusCallback->GetTemplateId().has_value()) {
                continue;
            }
            callbackTemplateId = continuousAuthStatusCallback->GetTemplateId().value();
            if (templateId != callbackTemplateId) {
                continue;
            }
            ret = continuousAuthStatusCallback->SetCallback(::taihe::optional<::taihe::callback<void(bool isAuthPassed,
                    ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>> {
                std::in_place_t {}, callback });
            if (ret != SUCCESS) {
                IAM_LOGE("SetCallback fail, ret:%{public}d", ret);
                return ret;
            }
            hasSameCallback = true;
        }
    }

    if (!hasSameCallback) {
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t StatusMonitor::OffContinuousAuthChange(::taihe::optional_view<::taihe::callback<void(bool isAuthPassed,
        ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>>
        callback)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (!callback.has_value()) {
        for (auto &continuousAuthStatusCallback : continuousAuthStatusCallbacks_) {
            int32_t ret = CompanionDeviceAuthClient::GetInstance().UnsubscribeContinuousAuthStatusChange(
                continuousAuthStatusCallback);
            if (ret != SUCCESS) {
                IAM_LOGE("UnsubscribeContinuousAuthStatusChange fail");
                return ret;
            }
            continuousAuthStatusCallback->ClearCallback();
        }
        continuousAuthStatusCallbacks_ = {};
    } else {
        for (auto it = continuousAuthStatusCallbacks_.begin(); it != continuousAuthStatusCallbacks_.end();) {
            // clang-format off
            if (!(*it)->HasSameCallback(::taihe::optional<::taihe::callback<void(bool isAuthPassed,
                ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>> {
                    std::in_place_t {}, callback.value()
                })) {
                ++it;
                continue;
            }
            // clang-format on
            (*it)->RemoveSingleCallback(::taihe::optional<::taihe::callback<void(bool isAuthPassed,
                    ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>> {
                std::in_place_t {}, callback.value() });
            if ((*it)->HasCallback()) {
                ++it;
                continue;
            }
            int32_t ret = CompanionDeviceAuthClient::GetInstance().UnsubscribeContinuousAuthStatusChange(*it);
            if (ret != SUCCESS) {
                IAM_LOGE("UnsubscribeContinuousAuthStatusChange fail");
                return ret;
            }
            it = continuousAuthStatusCallbacks_.erase(it);
        }
    }
    return SUCCESS;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS