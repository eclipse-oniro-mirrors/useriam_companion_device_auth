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

#include "ohos.userIAM.companionDeviceAuth.impl.hpp"
#include "ohos.userIAM.companionDeviceAuth.proj.hpp"
#include "stdexcept"

#include "ani_device_select_callback.h"
#include "companion_device_auth_ani_helper.h"
#include "companion_device_auth_common_defines.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "status_monitor.h"
#include "taihe/runtime.hpp"

#define LOG_TAG "COMPANION_DEVICE_AUTH_ANI"

namespace CompanionDeviceAuth = OHOS::UserIam::CompanionDeviceAuth;

namespace {
class StatusMonitorImpl {
public:
    explicit StatusMonitorImpl(int32_t localUserId)
        : statusMonitor_(CompanionDeviceAuth::MakeShared<CompanionDeviceAuth::StatusMonitor>(localUserId))
    {
    }

    ::taihe::array<::ohos::userIAM::companionDeviceAuth::TemplateStatus> getTemplateStatusSync()
    {
        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            return {};
        }
        std::vector<CompanionDeviceAuth::ClientTemplateStatus> clientTemplateStatusList;

        int32_t ret = statusMonitor_->GetTemplateStatus(clientTemplateStatusList);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("getTemplateStatus fail");
            return {};
        }

        std::vector<::ohos::userIAM::companionDeviceAuth::TemplateStatus> temp;
        ani_env *env = ::taihe::get_env();
        for (size_t i = 0; i < clientTemplateStatusList.size(); ++i) {
            ::ohos::userIAM::companionDeviceAuth::TemplateStatus templateStatus =
                CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ConvertTemplateStatus(clientTemplateStatusList[i],
                    env);
            temp.push_back(templateStatus);
        }
        ::taihe::array<::ohos::userIAM::companionDeviceAuth::TemplateStatus> result =
            ::taihe::array<::ohos::userIAM::companionDeviceAuth::TemplateStatus>(taihe::copy_data_t {}, temp.data(),
                temp.size());
        return result;
    }

    void onTemplateChange(::taihe::callback_view<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>
            callback)
    {
        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            return;
        }
        int32_t ret = statusMonitor_->OnTemplateChange(callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OnTemplateChange fail");
            return;
        }
    }

    void offTemplateChange(::taihe::optional_view<::taihe::callback<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>>
            callback)
    {
        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            return;
        }
        int32_t ret = statusMonitor_->OffTemplateChange(callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OnTemplateChange fail");
            return;
        }
    }

    void onContinuousAuthChange(::ohos::userIAM::companionDeviceAuth::ContinuousAuthParam const &param,
        ::taihe::callback_view<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>
            callback)
    {
        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            return;
        }
        int32_t ret = statusMonitor_->OnContinuousAuthChange(param, callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OnContinuousAuthChange fail");
            return;
        }
    }

    void offContinuousAuthChange(::taihe::optional_view<::taihe::callback<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>>
            callback)
    {
        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            return;
        }
        int32_t ret = statusMonitor_->OffContinuousAuthChange(callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OffContinuousAuthChange fail");
            return;
        }
    }

    void onAvailableDeviceChange(::taihe::callback_view<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>
            callback)
    {
        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            return;
        }
        int32_t ret = statusMonitor_->OnAvailableDeviceChange(callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OnAvailableDeviceChange fail");
            return;
        }
    }

    void offAvailableDeviceChange(::taihe::optional_view<::taihe::callback<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>>
            callback)
    {
        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            return;
        }
        int32_t ret = statusMonitor_->OffAvailableDeviceChange(callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OffAvailableDeviceChange fail");
            return;
        }
    }

private:
    std::shared_ptr<CompanionDeviceAuth::StatusMonitor> statusMonitor_ { nullptr };
};

::ohos::userIAM::companionDeviceAuth::StatusMonitor getStatusMonitor(int32_t localUserId)
{
    IAM_LOGI("start");
    auto statusMonitor =
        taihe::make_holder<StatusMonitorImpl, ::ohos::userIAM::companionDeviceAuth::StatusMonitor>(localUserId);
    return statusMonitor;
}

void updateEnabledBusinessIdsSync(::taihe::array_view<uint8_t> templateId,
    ::taihe::array_view<int32_t> enabledBusinessIds)
{
    uint64_t clientTemplateId = CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ConvertAniTemplateId(templateId);
    std::vector<int32_t> clientEnabledBusinessIds =
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ConvertArrayToInt32Vector(enabledBusinessIds);
    int32_t ret = CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().UpdateTemplateEnabledBusinessIds(
        clientTemplateId, clientEnabledBusinessIds);
    if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
        IAM_LOGE("UpdateEnabledBusinessIds fail");
    }
}

void registerDeviceSelectCallback(
    ::taihe::callback_view<::ohos::userIAM::companionDeviceAuth::DeviceSelectResult(int32_t selectPurpose)> callback)
{
    auto deviceSelectCallback = CompanionDeviceAuth::MakeShared<CompanionDeviceAuth::AniDeviceSelectCallback>();
    if (deviceSelectCallback == nullptr) {
        IAM_LOGE("deviceSelectCallback is null");
        return;
    }

    deviceSelectCallback->SetCallback(::taihe::optional<
        ::taihe::callback<::ohos::userIAM::companionDeviceAuth::DeviceSelectResult(int32_t selectPurpose)>> {
        std::in_place_t {}, callback });

    int32_t ret = CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().RegisterDeviceSelectCallback(
        deviceSelectCallback);
    if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
        IAM_LOGE("RegisterDeviceSelectCallback fail");
    }
}

void unregisterDeviceSelectCallback()
{
    int32_t ret = CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().UnregisterDeviceSelectCallback();
    if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
        IAM_LOGE("UnregisterDeviceSelectCallback fail");
    }
}
} // namespace

TH_EXPORT_CPP_API_getStatusMonitor(getStatusMonitor);
TH_EXPORT_CPP_API_updateEnabledBusinessIdsSync(updateEnabledBusinessIdsSync);
TH_EXPORT_CPP_API_registerDeviceSelectCallback(registerDeviceSelectCallback);
TH_EXPORT_CPP_API_unregisterDeviceSelectCallback(unregisterDeviceSelectCallback);