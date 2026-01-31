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
#include "tokenid_kit.h"

#include "taihe/runtime.hpp"

#include "iam_check.h"
#include "iam_logger.h"

#include "status_monitor.h"
#include "ani_device_select_callback.h"
#include "companion_device_auth_ani_helper.h"
#include "ohos.userIAM.companionDeviceAuth.impl.hpp"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "CDA_ANI"

namespace CompanionDeviceAuth = OHOS::UserIam::CompanionDeviceAuth;
namespace TaiheCompanionDeviceAuth = ::ohos::userIAM::companionDeviceAuth;

namespace {
int32_t CheckPermission()
{
    using namespace OHOS::Security::AccessToken;
    uint64_t fullTokenId = OHOS::IPCSkeleton::GetCallingFullTokenID();
    AccessTokenID tokenId = fullTokenId & CompanionDeviceAuth::TOKEN_ID_LOW_MASK;

    if (AccessTokenKit::VerifyAccessToken(tokenId, CompanionDeviceAuth::USE_USER_IDM_PERMISSION) != RET_SUCCESS) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        return CompanionDeviceAuth::CHECK_PERMISSION_FAILED;
    }

    bool checkRet = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (!checkRet || callingType != OHOS::Security::AccessToken::TOKEN_HAP) {
        IAM_LOGE("the caller is not system application");
        return CompanionDeviceAuth::CHECK_SYSTEM_PERMISSION_FAILED;
    }
    return CompanionDeviceAuth::SUCCESS;
}

using TaiheTemplateStatusCallback = ::taihe::callback<void(
    ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>;
using TaiheAvailableDeviceStatusCallback = ::taihe::callback<void(
    ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>;
using TaiheContinuousAuthStatusCallback = ::taihe::callback<void(
    bool isAuthPassed, ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>;

using AniStatusMonitor = CompanionDeviceAuth::StatusMonitor<
    TaiheTemplateStatusCallback,
    TaiheAvailableDeviceStatusCallback,
    TaiheContinuousAuthStatusCallback>;

using AniTemplateStatusCallback = CompanionDeviceAuth::TemplateStatusCallbackWrapper<TaiheTemplateStatusCallback>;
using AniAvailableDeviceStatusCallback =
    CompanionDeviceAuth::AvailableDeviceStatusCallbackWrapper<TaiheAvailableDeviceStatusCallback>;
using AniContinuousAuthStatusCallback =
    CompanionDeviceAuth::ContinuousAuthStatusCallbackWrapper<TaiheContinuousAuthStatusCallback>;

class StatusMonitorImpl {
public:
    explicit StatusMonitorImpl(int32_t localUserId) : statusMonitor_(localUserId) {}

    ::taihe::array<TaiheCompanionDeviceAuth::TemplateStatus> getTemplateStatusSync()
    {
        IAM_LOGI("start");
        int32_t checkPermission = CheckPermission();
        if (checkPermission != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(checkPermission);
            return {};
        }

        std::vector<CompanionDeviceAuth::ClientTemplateStatus> clientTemplateStatusList;
        int32_t ret = statusMonitor_.GetTemplateStatus(clientTemplateStatusList);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("getTemplateStatus fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return {};
        }

        std::vector<TaiheCompanionDeviceAuth::TemplateStatus> temp;
        ani_env *env = ::taihe::get_env();
        for (size_t i = 0; i < clientTemplateStatusList.size(); ++i) {
            TaiheCompanionDeviceAuth::TemplateStatus templateStatus =
                CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ConvertTemplateStatus(clientTemplateStatusList[i],
                    env);
            temp.push_back(templateStatus);
        }
        ::taihe::array<TaiheCompanionDeviceAuth::TemplateStatus> result =
            ::taihe::array<TaiheCompanionDeviceAuth::TemplateStatus>(taihe::copy_data_t {}, temp.data(),
                temp.size());
        IAM_LOGI("end");
        return result;
    }

    void onTemplateChange(::taihe::callback_view<void(
        ::taihe::array_view<TaiheCompanionDeviceAuth::TemplateStatus> templateStatusList)> callback)
    {
        IAM_LOGI("start");
        int32_t checkPermission = CheckPermission();
        if (checkPermission != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(checkPermission);
            return;
        }

        int32_t ret = statusMonitor_.OnTemplateChange(std::make_shared<AniTemplateStatusCallback>(callback));
        if (ret != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("OnTemplateChange fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("end");
    }

    void offTemplateChange(::taihe::optional_view<::taihe::callback<void(
        ::taihe::array_view<TaiheCompanionDeviceAuth::TemplateStatus> templateStatusList)>> callback)
    {
        IAM_LOGI("start");
        int32_t checkPermission = CheckPermission();
        if (checkPermission != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(checkPermission);
            return;
        }

        std::shared_ptr<AniTemplateStatusCallback> aniCallback = nullptr;
        if (callback.has_value()) {
            aniCallback = std::make_shared<AniTemplateStatusCallback>(*callback);
        }

        int32_t ret = statusMonitor_.OffTemplateChange(aniCallback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OffTemplateChange fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("end");
    }

    void onAvailableDeviceChange(::taihe::callback_view<void(
            ::taihe::array_view<TaiheCompanionDeviceAuth::DeviceStatus> deviceStatusList)>
            callback)
    {
        IAM_LOGI("start");
        int32_t checkPermission = CheckPermission();
        if (checkPermission != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(checkPermission);
            return;
        }

        int32_t ret = statusMonitor_.OnAvailableDeviceChange(
            std::make_shared<AniAvailableDeviceStatusCallback>(callback));
        if (ret != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("OnAvailableDeviceChange fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("end");
    }

    void offAvailableDeviceChange(::taihe::optional_view<::taihe::callback<void(
            ::taihe::array_view<TaiheCompanionDeviceAuth::DeviceStatus> deviceStatusList)>>
            callback)
    {
        IAM_LOGI("start");
        int32_t checkPermission = CheckPermission();
        if (checkPermission != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(checkPermission);
            return;
        }

        std::shared_ptr<AniAvailableDeviceStatusCallback> aniCallback = nullptr;
        if (callback.has_value()) {
            aniCallback = std::make_shared<AniAvailableDeviceStatusCallback>(*callback);
        }

        int32_t ret = statusMonitor_.OffAvailableDeviceChange(aniCallback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OffAvailableDeviceChange fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("end");
    }

    void onContinuousAuthChange(TaiheCompanionDeviceAuth::ContinuousAuthParam const &param,
        ::taihe::callback_view<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)> callback)
    {
        IAM_LOGI("start");
        int32_t checkPermission = CheckPermission();
        if (checkPermission != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(checkPermission);
            return;
        }

        std::optional<uint64_t> templateId = std::nullopt;
        if (param.templateId.has_value()) {
            templateId = CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ConvertAniTemplateId(*param.templateId);
        }
        int32_t ret = statusMonitor_.OnContinuousAuthChange(
            templateId, std::make_shared<AniContinuousAuthStatusCallback>(callback));
        if (ret != CompanionDeviceAuth::SUCCESS) {
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
        int32_t checkPermission = CheckPermission();
        if (checkPermission != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(checkPermission);
            return;
        }

        std::shared_ptr<AniContinuousAuthStatusCallback> aniCallback = nullptr;
        if (callback.has_value()) {
            aniCallback = std::make_shared<AniContinuousAuthStatusCallback>(*callback);
        }

        int32_t ret = statusMonitor_.OffContinuousAuthChange(aniCallback);
        if (ret != CompanionDeviceAuth::ResultCode::SUCCESS) {
            IAM_LOGE("OffContinuousAuthChange fail");
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("end");
    }

private:
    AniStatusMonitor statusMonitor_;
};

TaiheCompanionDeviceAuth::StatusMonitor getStatusMonitor(int32_t localUserId)
{
    IAM_LOGI("start");
    const int32_t invalidUserId = -1;

    int32_t checkPermission = CheckPermission();
    if (checkPermission != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(checkPermission);
        return taihe::make_holder<StatusMonitorImpl, TaiheCompanionDeviceAuth::StatusMonitor>(invalidUserId);
    }

    int32_t ret = AniStatusMonitor::CheckUserId(localUserId);
    if (ret != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("CheckUserId fail, ret:%{public}d", ret);
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
        return taihe::make_holder<StatusMonitorImpl, TaiheCompanionDeviceAuth::StatusMonitor>(invalidUserId);
    }

    IAM_LOGI("end");
    return taihe::make_holder<StatusMonitorImpl, TaiheCompanionDeviceAuth::StatusMonitor>(localUserId);
}

void updateEnabledBusinessIdsSync(::taihe::array_view<uint8_t> templateId,
    ::taihe::array_view<int32_t> enabledBusinessIds)
{
    IAM_LOGI("start");
    int32_t checkPermission = CheckPermission();
    if (checkPermission != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(checkPermission);
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
    ::taihe::callback_view<TaiheCompanionDeviceAuth::DeviceSelectResult(int32_t selectPurpose)> callback)
{
    IAM_LOGI("start");
    int32_t checkPermission = CheckPermission();
    if (checkPermission != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(checkPermission);
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
        ::taihe::callback<TaiheCompanionDeviceAuth::DeviceSelectResult(int32_t selectPurpose)>> {
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
    int32_t checkPermission = CheckPermission();
    if (checkPermission != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(checkPermission);
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
