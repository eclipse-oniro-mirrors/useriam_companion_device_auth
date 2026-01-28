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

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "ani_device_select_callback.h"
#include "companion_device_auth_ani_helper.h"
#include "companion_device_auth_client.h"
#include "companion_device_auth_common_defines.h"
#include "ohos.userIAM.companionDeviceAuth.impl.hpp"
#include "ohos.userIAM.companionDeviceAuth.proj.hpp"
#include "status_monitor.h"
#include "stdexcept"
#include "taihe/runtime.hpp"
#include "tokenid_kit.h"

#define LOG_TAG "CDA_ANI"

namespace CompanionDeviceAuth = OHOS::UserIam::CompanionDeviceAuth;

namespace {
bool CheckUseUserIdmPermission()
{
    IAM_LOGI("start");
    using namespace OHOS::Security::AccessToken;
    uint64_t fullTokenId = OHOS::IPCSkeleton::GetCallingFullTokenID();
    AccessTokenID tokenId = fullTokenId & CompanionDeviceAuth::TOKEN_ID_LOW_MASK;
    int32_t ret = AccessTokenKit::VerifyAccessToken(tokenId, CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
    if (ret != RET_SUCCESS) {
        IAM_LOGI("VerifyAccessToken fail");
        return false;
    }
    IAM_LOGI("success");
    return true;
}

bool CheckCallerIsSystemApp()
{
    IAM_LOGI("start");
    using namespace OHOS::Security::AccessToken;
    uint64_t fullTokenId = OHOS::IPCSkeleton::GetCallingFullTokenID();
    bool checkRet = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    AccessTokenID tokenId = fullTokenId & CompanionDeviceAuth::TOKEN_ID_LOW_MASK;
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (!checkRet || callingType != OHOS::Security::AccessToken::TOKEN_HAP) {
        IAM_LOGI("the caller is not system application");
        return false;
    }
    IAM_LOGI("success");
    return true;
}

class StatusMonitorImpl {
public:
    explicit StatusMonitorImpl(int32_t localUserId)
        : statusMonitor_(std::make_shared<CompanionDeviceAuth::StatusMonitor>(localUserId))
    {
    }

    ::taihe::array<::ohos::userIAM::companionDeviceAuth::TemplateStatus> getTemplateStatusSync()
    {
        IAM_LOGI("start");
        if (!CheckUseUserIdmPermission()) {
            IAM_LOGE("CheckUseUserIdmPermission fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_PERMISSION_FAILED);
            return {};
        }

        if (!CheckCallerIsSystemApp()) {
            IAM_LOGE("CheckCallerIsSystemApp fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED);
            return {};
        }

        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::ResultCode::GENERAL_ERROR);
            return {};
        }
        std::vector<CompanionDeviceAuth::ClientTemplateStatus> clientTemplateStatusList;
        int32_t ret = statusMonitor_->GetTemplateStatus(clientTemplateStatusList);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("getTemplateStatus fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
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
        IAM_LOGI("end");
        return result;
    }

    void onTemplateChange(::taihe::callback_view<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>
            callback)
    {
        IAM_LOGI("start");
        if (!CheckUseUserIdmPermission()) {
            IAM_LOGE("CheckUseUserIdmPermission fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_PERMISSION_FAILED);
            return;
        }

        if (!CheckCallerIsSystemApp()) {
            IAM_LOGE("CheckCallerIsSystemApp fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED);
            return;
        }

        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::ResultCode::GENERAL_ERROR);
            return;
        }
        int32_t ret = statusMonitor_->OnTemplateChange(callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OnTemplateChange fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("end");
    }

    void offTemplateChange(::taihe::optional_view<::taihe::callback<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>>
            callback)
    {
        IAM_LOGI("start");
        if (!CheckUseUserIdmPermission()) {
            IAM_LOGE("CheckUseUserIdmPermission fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_PERMISSION_FAILED);
            return;
        }

        if (!CheckCallerIsSystemApp()) {
            IAM_LOGE("CheckCallerIsSystemApp fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED);
            return;
        }

        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::ResultCode::GENERAL_ERROR);
            return;
        }
        int32_t ret = statusMonitor_->OffTemplateChange(callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OnTemplateChange fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("end");
    }

    void onContinuousAuthChange(::ohos::userIAM::companionDeviceAuth::ContinuousAuthParam const &param,
        ::taihe::callback_view<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>
            callback)
    {
        IAM_LOGI("start");
        if (!CheckUseUserIdmPermission()) {
            IAM_LOGE("CheckUseUserIdmPermission fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_PERMISSION_FAILED);
            return;
        }

        if (!CheckCallerIsSystemApp()) {
            IAM_LOGE("CheckCallerIsSystemApp fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED);
            return;
        }

        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::ResultCode::GENERAL_ERROR);
            return;
        }
        int32_t ret = statusMonitor_->OnContinuousAuthChange(param, callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OnContinuousAuthChange fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("end");
    }

    void offContinuousAuthChange(::taihe::optional_view<::taihe::callback<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>>
            callback)
    {
        IAM_LOGI("start");
        if (!CheckUseUserIdmPermission()) {
            IAM_LOGE("CheckUseUserIdmPermission fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_PERMISSION_FAILED);
            return;
        }

        if (!CheckCallerIsSystemApp()) {
            IAM_LOGE("CheckCallerIsSystemApp fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED);
            return;
        }

        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::ResultCode::GENERAL_ERROR);
            return;
        }
        int32_t ret = statusMonitor_->OffContinuousAuthChange(callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OffContinuousAuthChange fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("end");
    }

    void onAvailableDeviceChange(::taihe::callback_view<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>
            callback)
    {
        IAM_LOGI("start");
        if (!CheckUseUserIdmPermission()) {
            IAM_LOGE("CheckUseUserIdmPermission fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_PERMISSION_FAILED);
            return;
        }

        if (!CheckCallerIsSystemApp()) {
            IAM_LOGE("CheckCallerIsSystemApp fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED);
            return;
        }

        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::ResultCode::GENERAL_ERROR);
            return;
        }
        int32_t ret = statusMonitor_->OnAvailableDeviceChange(callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OnAvailableDeviceChange fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("end");
    }

    void offAvailableDeviceChange(::taihe::optional_view<::taihe::callback<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>>
            callback)
    {
        IAM_LOGI("start");
        if (!CheckUseUserIdmPermission()) {
            IAM_LOGE("CheckUseUserIdmPermission fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_PERMISSION_FAILED);
            return;
        }

        if (!CheckCallerIsSystemApp()) {
            IAM_LOGE("CheckCallerIsSystemApp fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED);
            return;
        }

        if (statusMonitor_ == nullptr) {
            IAM_LOGE("statusMonitor_ is null");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
                CompanionDeviceAuth::ResultCode::GENERAL_ERROR);
            return;
        }
        int32_t ret = statusMonitor_->OffAvailableDeviceChange(callback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OffAvailableDeviceChange fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("end");
    }

private:
    std::shared_ptr<CompanionDeviceAuth::StatusMonitor> statusMonitor_ { nullptr };
};

::ohos::userIAM::companionDeviceAuth::StatusMonitor getStatusMonitor(int32_t localUserId)
{
    IAM_LOGI("start");
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
            CompanionDeviceAuth::CHECK_PERMISSION_FAILED);
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
            CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED);
    }

    bool isUserIdValid = false;
    int32_t ret =
        CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().CheckLocalUserIdValid(localUserId, isUserIdValid);
    if (ret != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("CheckLocalUserIdValid fail, ret:%{public}d", ret);
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
    }

    if (!isUserIdValid) {
        IAM_LOGE("input local user id is invalid");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(CompanionDeviceAuth::USER_ID_NOT_FOUND);
    }

    auto statusMonitor =
        taihe::make_holder<StatusMonitorImpl, ::ohos::userIAM::companionDeviceAuth::StatusMonitor>(localUserId);
    IAM_LOGI("end");
    return statusMonitor;
}

void updateEnabledBusinessIdsSync(::taihe::array_view<uint8_t> templateId,
    ::taihe::array_view<int32_t> enabledBusinessIds)
{
    IAM_LOGI("start");
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
            CompanionDeviceAuth::CHECK_PERMISSION_FAILED);
        return;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
            CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED);
        return;
    }

    uint64_t clientTemplateId = CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ConvertAniTemplateId(templateId);
    std::vector<int32_t> clientEnabledBusinessIds =
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ConvertArrayToInt32Vector(enabledBusinessIds);
    int32_t ret = CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().UpdateTemplateEnabledBusinessIds(
        clientTemplateId, clientEnabledBusinessIds);
    if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
        IAM_LOGE("UpdateEnabledBusinessIds fail");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
        return;
    }
    IAM_LOGI("end");
}

void registerDeviceSelectCallback(
    ::taihe::callback_view<::ohos::userIAM::companionDeviceAuth::DeviceSelectResult(int32_t selectPurpose)> callback)
{
    IAM_LOGI("start");
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
            CompanionDeviceAuth::CHECK_PERMISSION_FAILED);
        return;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
            CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED);
        return;
    }

    auto deviceSelectCallback = std::make_shared<CompanionDeviceAuth::AniDeviceSelectCallback>();
    if (deviceSelectCallback == nullptr) {
        IAM_LOGE("deviceSelectCallback is null");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
            CompanionDeviceAuth::ResultCode::GENERAL_ERROR);
        return;
    }

    deviceSelectCallback->SetCallback(::taihe::optional<
        ::taihe::callback<::ohos::userIAM::companionDeviceAuth::DeviceSelectResult(int32_t selectPurpose)>> {
        std::in_place_t {}, callback });

    int32_t ret = CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().RegisterDeviceSelectCallback(
        deviceSelectCallback);
    if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
        IAM_LOGE("RegisterDeviceSelectCallback fail");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
        return;
    }
    IAM_LOGI("end");
}

void unregisterDeviceSelectCallback()
{
    IAM_LOGI("start");
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
            CompanionDeviceAuth::CHECK_PERMISSION_FAILED);
        return;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(
            CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED);
        return;
    }

    int32_t ret = CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().UnregisterDeviceSelectCallback();
    if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
        IAM_LOGE("UnregisterDeviceSelectCallback fail");
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
        return;
    }
    IAM_LOGI("end");
}
} // namespace

TH_EXPORT_CPP_API_getStatusMonitor(getStatusMonitor);
TH_EXPORT_CPP_API_updateEnabledBusinessIdsSync(updateEnabledBusinessIdsSync);
TH_EXPORT_CPP_API_registerDeviceSelectCallback(registerDeviceSelectCallback);
TH_EXPORT_CPP_API_unregisterDeviceSelectCallback(unregisterDeviceSelectCallback);