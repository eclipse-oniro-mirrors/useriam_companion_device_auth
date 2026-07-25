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
#include "taihe/runtime.hpp"
#include "tokenid_kit.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "ani_device_select_callback.h"
#include "ani_passcode_prompt_callback.h"
#include "companion_device_auth_ani_helper.h"
#include "ohos.userIAM.companionDeviceAuth.impl.hpp"
#include "status_monitor.h"

#define LOG_TAG "CDA_ANI"
#define LOG_FILE_ID LOG_FILE_CDA_ANI_IMPL

namespace CompanionDeviceAuth = OHOS::UserIam::CompanionDeviceAuth;
namespace TaiheCompanionDeviceAuth = ::ohos::userIAM::companionDeviceAuth;

namespace {
int32_t CheckPermission(const std::string &permission)
{
    using namespace OHOS::Security::AccessToken;
    uint64_t fullTokenId = OHOS::IPCSkeleton::GetCallingFullTokenID();
    AccessTokenID tokenId = fullTokenId & CompanionDeviceAuth::TOKEN_ID_LOW_MASK;

    if (AccessTokenKit::VerifyAccessToken(tokenId, permission) != RET_SUCCESS) {
        IAM_LOGE("check permission %{public}s failed", permission.c_str());
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
using TaiheAvailableDeviceStatusCallback =
    ::taihe::callback<void(::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>;
using TaiheContinuousAuthStatusCallback = ::taihe::callback<void(bool isAuthPassed,
    ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>;

using AniStatusMonitor = CompanionDeviceAuth::StatusMonitor<TaiheTemplateStatusCallback,
    TaiheAvailableDeviceStatusCallback, TaiheContinuousAuthStatusCallback>;

using AniTemplateStatusCallback = CompanionDeviceAuth::TemplateStatusCallbackWrapper<TaiheTemplateStatusCallback>;
using AniAvailableDeviceStatusCallback =
    CompanionDeviceAuth::AvailableDeviceStatusCallbackWrapper<TaiheAvailableDeviceStatusCallback>;
using AniContinuousAuthStatusCallback =
    CompanionDeviceAuth::ContinuousAuthStatusCallbackWrapper<TaiheContinuousAuthStatusCallback>;

class StatusMonitorImpl {
public:
    explicit StatusMonitorImpl(int32_t localUserId) : statusMonitor_(localUserId)
    {
    }

    int32_t getTemplateStatusInternal(std::vector<CompanionDeviceAuth::ClientTemplateStatus> &clientTemplateStatusList)
    {
        int32_t checkPermission = CheckPermission(CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
        ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);
        int32_t ret = statusMonitor_.GetTemplateStatus(clientTemplateStatusList);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("getTemplateStatus fail, ret:%{public}d", ret);
        }
        return ret;
    }

    ::taihe::array<TaiheCompanionDeviceAuth::TemplateStatus> getTemplateStatusSync()
    {
        IAM_LOGI("start");
        std::vector<CompanionDeviceAuth::ClientTemplateStatus> clientTemplateStatusList;
        int32_t ret = getTemplateStatusInternal(clientTemplateStatusList);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return {};
        }

        std::vector<TaiheCompanionDeviceAuth::TemplateStatus> temp;
        ani_env *env = ::taihe::get_env();
        if (env == nullptr) {
            IAM_LOGE("(env != nullptr) check fail, return");
            return {};
        }
        for (size_t i = 0; i < clientTemplateStatusList.size(); ++i) {
            TaiheCompanionDeviceAuth::TemplateStatus templateStatus =
                CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ConvertTemplateStatus(clientTemplateStatusList[i],
                    env);
            temp.push_back(templateStatus);
        }
        ::taihe::array<TaiheCompanionDeviceAuth::TemplateStatus> result =
            ::taihe::array<TaiheCompanionDeviceAuth::TemplateStatus>(taihe::copy_data_t {}, temp.data(), temp.size());
        IAM_LOGI("success");
        return result;
    }

    ::taihe::array<TaiheCompanionDeviceAuth::TemplateStatus> getTemplateStatus()
    {
        return getTemplateStatusSync();
    }

    int32_t onTemplateChangeInternal(
        ::taihe::callback_view<void(::taihe::array_view<TaiheCompanionDeviceAuth::TemplateStatus> templateStatusList)>
            callback)
    {
        int32_t checkPermission = CheckPermission(CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
        ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);
        auto aniCallback = std::make_shared<AniTemplateStatusCallback>(callback);
        ENSURE_OR_RETURN_VAL(aniCallback != nullptr, CompanionDeviceAuth::GENERAL_ERROR);
        int32_t ret = statusMonitor_.OnTemplateChange(aniCallback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("OnTemplateChange fail, ret:%{public}d", ret);
        }
        return ret;
    }

    void onTemplateChange(
        ::taihe::callback_view<void(::taihe::array_view<TaiheCompanionDeviceAuth::TemplateStatus> templateStatusList)>
            callback)
    {
        IAM_LOGI("start");
        int32_t ret = onTemplateChangeInternal(callback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("success");
    }

    int32_t offTemplateChangeInternal(::taihe::optional_view<
        ::taihe::callback<void(::taihe::array_view<TaiheCompanionDeviceAuth::TemplateStatus> templateStatusList)>>
            callback)
    {
        int32_t checkPermission = CheckPermission(CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
        ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);

        std::shared_ptr<AniTemplateStatusCallback> aniCallback = nullptr;
        if (callback.has_value()) {
            aniCallback = std::make_shared<AniTemplateStatusCallback>(*callback);
            ENSURE_OR_RETURN_VAL(aniCallback != nullptr, CompanionDeviceAuth::GENERAL_ERROR);
        }

        int32_t ret = statusMonitor_.OffTemplateChange(aniCallback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("OffTemplateChange fail, ret:%{public}d", ret);
        }
        return ret;
    }

    void offTemplateChange(::taihe::optional_view<
        ::taihe::callback<void(::taihe::array_view<TaiheCompanionDeviceAuth::TemplateStatus> templateStatusList)>>
            callback)
    {
        IAM_LOGI("start");
        int32_t ret = offTemplateChangeInternal(callback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("success");
    }

    int32_t onAvailableDeviceChangeInternal(
        ::taihe::callback_view<void(::taihe::array_view<TaiheCompanionDeviceAuth::DeviceStatus> deviceStatusList)>
            callback)
    {
        int32_t checkPermission = CheckPermission(CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
        ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);
        auto aniCallback = std::make_shared<AniAvailableDeviceStatusCallback>(callback);
        ENSURE_OR_RETURN_VAL(aniCallback != nullptr, CompanionDeviceAuth::GENERAL_ERROR);
        int32_t ret = statusMonitor_.OnAvailableDeviceChange(aniCallback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("OnAvailableDeviceChange fail, ret:%{public}d", ret);
        }
        return ret;
    }

    void onAvailableDeviceChange(
        ::taihe::callback_view<void(::taihe::array_view<TaiheCompanionDeviceAuth::DeviceStatus> deviceStatusList)>
            callback)
    {
        IAM_LOGI("start");
        int32_t ret = onAvailableDeviceChangeInternal(callback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("success");
    }

    int32_t offAvailableDeviceChangeInternal(::taihe::optional_view<
        ::taihe::callback<void(::taihe::array_view<TaiheCompanionDeviceAuth::DeviceStatus> deviceStatusList)>>
            callback)
    {
        int32_t checkPermission = CheckPermission(CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
        ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);

        std::shared_ptr<AniAvailableDeviceStatusCallback> aniCallback = nullptr;
        if (callback.has_value()) {
            aniCallback = std::make_shared<AniAvailableDeviceStatusCallback>(*callback);
            ENSURE_OR_RETURN_VAL(aniCallback != nullptr, CompanionDeviceAuth::GENERAL_ERROR);
        }

        int32_t ret = statusMonitor_.OffAvailableDeviceChange(aniCallback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("OffAvailableDeviceChange fail, ret:%{public}d", ret);
        }
        return ret;
    }

    void offAvailableDeviceChange(::taihe::optional_view<
        ::taihe::callback<void(::taihe::array_view<TaiheCompanionDeviceAuth::DeviceStatus> deviceStatusList)>>
            callback)
    {
        IAM_LOGI("start");
        int32_t ret = offAvailableDeviceChangeInternal(callback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("success");
    }

    int32_t onContinuousAuthChangeInternal(TaiheCompanionDeviceAuth::ContinuousAuthParam const &param,
        ::taihe::callback_view<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>
            callback)
    {
        int32_t checkPermission = CheckPermission(CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
        ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);

        std::optional<uint64_t> templateId = std::nullopt;
        if (param.templateId.has_value()) {
            templateId = CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ConvertAniTemplateId(*param.templateId);
            if (!templateId.has_value()) {
                IAM_LOGE("ConvertAniTemplateId fail");
                return CompanionDeviceAuth::INVALID_PARAMETERS;
            }
        }
        auto aniCallback = std::make_shared<AniContinuousAuthStatusCallback>(callback);
        ENSURE_OR_RETURN_VAL(aniCallback != nullptr, CompanionDeviceAuth::GENERAL_ERROR);
        int32_t ret = statusMonitor_.OnContinuousAuthChange(templateId, aniCallback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("OnContinuousAuthChange fail, ret:%{public}d", ret);
        }
        return ret;
    }

    void onContinuousAuthChange(TaiheCompanionDeviceAuth::ContinuousAuthParam const &param,
        ::taihe::callback_view<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>
            callback)
    {
        IAM_LOGI("start");
        int32_t ret = onContinuousAuthChangeInternal(param, callback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("success");
    }

    int32_t offContinuousAuthChangeInternal(::taihe::optional_view<::taihe::callback<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>>
            callback)
    {
        int32_t checkPermission = CheckPermission(CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
        ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);

        std::shared_ptr<AniContinuousAuthStatusCallback> aniCallback = nullptr;
        if (callback.has_value()) {
            aniCallback = std::make_shared<AniContinuousAuthStatusCallback>(*callback);
            ENSURE_OR_RETURN_VAL(aniCallback != nullptr, CompanionDeviceAuth::GENERAL_ERROR);
        }

        int32_t ret = statusMonitor_.OffContinuousAuthChange(aniCallback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            IAM_LOGE("OffContinuousAuthChange fail, ret:%{public}d", ret);
        }
        return ret;
    }

    void offContinuousAuthChange(::taihe::optional_view<::taihe::callback<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>>
            callback)
    {
        IAM_LOGI("start");
        int32_t ret = offContinuousAuthChangeInternal(callback);
        if (ret != CompanionDeviceAuth::SUCCESS) {
            CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
            return;
        }
        IAM_LOGI("success");
    }

private:
    AniStatusMonitor statusMonitor_;
};

int32_t getStatusMonitorInternal(int32_t localUserId)
{
    int32_t checkPermission = CheckPermission(CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);

    int32_t ret = AniStatusMonitor::CheckUserId(localUserId);
    if (ret != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("CheckUserId fail, ret:%{public}d", ret);
    }
    return ret;
}

TaiheCompanionDeviceAuth::StatusMonitor getStatusMonitor(int32_t localUserId)
{
    IAM_LOGI("start");
    const int32_t invalidUserId = -1;

    int32_t ret = getStatusMonitorInternal(localUserId);
    if (ret != CompanionDeviceAuth::SUCCESS) {
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
        return taihe::make_holder<StatusMonitorImpl, TaiheCompanionDeviceAuth::StatusMonitor>(invalidUserId);
    }

    IAM_LOGI("success");
    return taihe::make_holder<StatusMonitorImpl, TaiheCompanionDeviceAuth::StatusMonitor>(localUserId);
}

int32_t updateEnabledBusinessIdsSyncInternal(::taihe::array_view<uint8_t> templateId,
    ::taihe::array_view<int32_t> enabledBusinessIds)
{
    int32_t checkPermission = CheckPermission(CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);

    auto templateIdOpt = CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ConvertAniTemplateId(templateId);
    if (!templateIdOpt.has_value()) {
        IAM_LOGE("ConvertAniTemplateId fail");
        return CompanionDeviceAuth::INVALID_PARAMETERS;
    }
    uint64_t clientTemplateId = *templateIdOpt;
    std::vector<int32_t> clientEnabledBusinessIds =
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ConvertArrayToInt32Vector(enabledBusinessIds);
    int32_t ret = CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().UpdateTemplateEnabledBusinessIds(
        clientTemplateId, clientEnabledBusinessIds);
    if (ret != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("UpdateEnabledBusinessIds fail, ret:%{public}d", ret);
    }
    return ret;
}

void updateEnabledBusinessIdsSync(::taihe::array_view<uint8_t> templateId,
    ::taihe::array_view<int32_t> enabledBusinessIds)
{
    IAM_LOGI("start");
    int32_t ret = updateEnabledBusinessIdsSyncInternal(templateId, enabledBusinessIds);
    if (ret != CompanionDeviceAuth::SUCCESS) {
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
        return;
    }
    IAM_LOGI("success");
}

int32_t registerDeviceSelectCallbackInternal(
    ::taihe::callback_view<TaiheCompanionDeviceAuth::DeviceSelectResult(int32_t selectPurpose)> callback)
{
    int32_t checkPermission = CheckPermission(CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);

    auto deviceSelectCallback = std::make_shared<CompanionDeviceAuth::AniDeviceSelectCallback>();
    ENSURE_OR_RETURN_VAL(deviceSelectCallback != nullptr, CompanionDeviceAuth::GENERAL_ERROR);

    deviceSelectCallback->SetCallback(
        ::taihe::optional<::taihe::callback<TaiheCompanionDeviceAuth::DeviceSelectResult(int32_t selectPurpose)>> {
            std::in_place_t {}, callback });

    int32_t ret = CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().RegisterDeviceSelectCallback(
        deviceSelectCallback);
    if (ret != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("RegisterDeviceSelectCallback fail, ret:%{public}d", ret);
    }
    return ret;
}

void registerDeviceSelectCallback(
    ::taihe::callback_view<TaiheCompanionDeviceAuth::DeviceSelectResult(int32_t selectPurpose)> callback)
{
    IAM_LOGI("start");
    int32_t ret = registerDeviceSelectCallbackInternal(callback);
    if (ret != CompanionDeviceAuth::SUCCESS) {
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
        return;
    }
    IAM_LOGI("success");
}

int32_t unregisterDeviceSelectCallbackInternal()
{
    int32_t checkPermission = CheckPermission(CompanionDeviceAuth::USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);

    int32_t ret = CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().UnregisterDeviceSelectCallback();
    if (ret != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("UnregisterDeviceSelectCallback fail, ret:%{public}d", ret);
    }
    return ret;
}

void unregisterDeviceSelectCallback()
{
    IAM_LOGI("start");
    int32_t ret = unregisterDeviceSelectCallbackInternal();
    if (ret != CompanionDeviceAuth::SUCCESS) {
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
        return;
    }
    IAM_LOGI("success");
}

int32_t registerPasscodePromptCallbackInternal(
    ::taihe::callback_view<void(::taihe::callback_view<void(::taihe::array_view<uint8_t>)>,
        const TaiheCompanionDeviceAuth::PasscodePromptOptions &)>
        callback)
{
    int32_t checkPermission = CheckPermission(CompanionDeviceAuth::ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);

    auto passcodePromptCallback = std::make_shared<CompanionDeviceAuth::AniPasscodePromptCallback>();
    ENSURE_OR_RETURN_VAL(passcodePromptCallback != nullptr, CompanionDeviceAuth::GENERAL_ERROR);

    passcodePromptCallback->SetCallback(
        ::taihe::optional<::taihe::callback<void(::taihe::callback_view<void(::taihe::array_view<uint8_t>)>,
            const TaiheCompanionDeviceAuth::PasscodePromptOptions &)>> { std::in_place_t {}, callback });

    int32_t ret = CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().RegisterPasscodePromptCallback(
        passcodePromptCallback);
    if (ret != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("RegisterPasscodePromptCallback fail, ret:%{public}d", ret);
    }
    return ret;
}

void registerPasscodePromptCallback(
    ::taihe::callback_view<void(::taihe::callback_view<void(::taihe::array_view<uint8_t>)>,
        const TaiheCompanionDeviceAuth::PasscodePromptOptions &)>
        callback)
{
    IAM_LOGI("start");
    int32_t ret = registerPasscodePromptCallbackInternal(callback);
    if (ret != CompanionDeviceAuth::SUCCESS) {
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
        return;
    }
    IAM_LOGI("success");
}

int32_t unregisterPasscodePromptCallbackInternal()
{
    int32_t checkPermission = CheckPermission(CompanionDeviceAuth::ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == CompanionDeviceAuth::SUCCESS, checkPermission);

    int32_t ret = CompanionDeviceAuth::CompanionDeviceAuthClient::GetInstance().UnregisterPasscodePromptCallback();
    if (ret != CompanionDeviceAuth::SUCCESS) {
        IAM_LOGE("UnregisterPasscodePromptCallback fail, ret:%{public}d", ret);
    }
    return ret;
}

void unregisterPasscodePromptCallback()
{
    IAM_LOGI("start");
    int32_t ret = unregisterPasscodePromptCallbackInternal();
    if (ret != CompanionDeviceAuth::SUCCESS) {
        CompanionDeviceAuth::CompanionDeviceAuthAniHelper::ThrowBusinessError(ret);
        return;
    }
    IAM_LOGI("success");
}
} // namespace

TH_EXPORT_CPP_API_getStatusMonitor(getStatusMonitor);
TH_EXPORT_CPP_API_updateEnabledBusinessIdsSync(updateEnabledBusinessIdsSync);
TH_EXPORT_CPP_API_updateEnabledBusinessIds(updateEnabledBusinessIdsSync);
TH_EXPORT_CPP_API_registerDeviceSelectCallback(registerDeviceSelectCallback);
TH_EXPORT_CPP_API_unregisterDeviceSelectCallback(unregisterDeviceSelectCallback);
TH_EXPORT_CPP_API_registerPasscodePromptCallback(registerPasscodePromptCallback);
TH_EXPORT_CPP_API_unregisterPasscodePromptCallback(unregisterPasscodePromptCallback);
