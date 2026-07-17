/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "base_service_core.h"

#include <memory>
#include <new>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "adapter_manager.h"
#include "companion_manager_impl.h"
#include "cross_device_comm_manager_impl.h"
#include "security_command_adapter_impl.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "subscription_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_BASE_SERVICE_CORE

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<BaseServiceCore> BaseServiceCore::Create(
    const std::shared_ptr<SubscriptionManager> &subscriptionManager, const std::vector<BusinessId> &hostBusinessId,
    const std::vector<BusinessId> &companionBusinessId)
{
    IAM_LOGI("Start");
    ENSURE_OR_RETURN_VAL(subscriptionManager != nullptr, nullptr);

    auto core = std::shared_ptr<BaseServiceCore>(
        new (std::nothrow) BaseServiceCore(subscriptionManager, hostBusinessId, companionBusinessId));
    ENSURE_OR_RETURN_VAL(core != nullptr, nullptr);
    IAM_LOGI("End");
    return core;
}

BaseServiceCore::BaseServiceCore(std::shared_ptr<SubscriptionManager> subscriptionManager,
    const std::vector<BusinessId> &hostBusinessId, const std::vector<BusinessId> &companionBusinessId)
    : subscriptionManager_(std::move(subscriptionManager)),
      hostBusinessIds_(hostBusinessId),
      companionBusinessIds_(companionBusinessId)
{
}

bool BaseServiceCore::IsValidBusinessId(BusinessId businessId) const
{
    return std::find(hostBusinessIds_.begin(), hostBusinessIds_.end(), businessId) != hostBusinessIds_.end();
}

ResultCode BaseServiceCore::SubscribeAvailableDeviceStatus(int32_t localUserId,
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback)
{
    IAM_LOGI("Start");
    ENSURE_OR_RETURN_VAL(deviceStatusCallback != nullptr, ResultCode::INVALID_PARAMETERS);
    ENSURE_OR_RETURN_VAL(subscriptionManager_ != nullptr, ResultCode::GENERAL_ERROR);

    if (localUserId != GetUserIdManager().GetActiveUserId()) {
        IAM_LOGE("userId %{public}d is not the active user id %{public}d", localUserId,
            GetUserIdManager().GetActiveUserId());
        return ResultCode::GENERAL_ERROR;
    }

    subscriptionManager_->AddAvailableDeviceStatusCallback(localUserId, deviceStatusCallback);
    TaskRunnerManager::GetInstance().PostTaskOnResident([]() { GetCrossDeviceCommManager().RefreshDeviceStatus(); });
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode BaseServiceCore::UnsubscribeAvailableDeviceStatus(
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback)
{
    IAM_LOGI("Start");
    ENSURE_OR_RETURN_VAL(deviceStatusCallback != nullptr, ResultCode::INVALID_PARAMETERS);
    ENSURE_OR_RETURN_VAL(subscriptionManager_ != nullptr, ResultCode::GENERAL_ERROR);

    subscriptionManager_->RemoveAvailableDeviceStatusCallback(deviceStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode BaseServiceCore::SubscribeTemplateStatusChange(int32_t localUserId,
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback)
{
    IAM_LOGI("Start");
    ENSURE_OR_RETURN_VAL(templateStatusCallback != nullptr, ResultCode::INVALID_PARAMETERS);
    ENSURE_OR_RETURN_VAL(subscriptionManager_ != nullptr, ResultCode::GENERAL_ERROR);

    if (localUserId != GetUserIdManager().GetActiveUserId()) {
        IAM_LOGE("userId %{public}d is not the active user id %{public}d", localUserId,
            GetUserIdManager().GetActiveUserId());
        return ResultCode::GENERAL_ERROR;
    }

    subscriptionManager_->AddTemplateStatusCallback(localUserId, templateStatusCallback);
    TaskRunnerManager::GetInstance().PostTaskOnResident([]() { GetCrossDeviceCommManager().RefreshDeviceStatus(); });
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode BaseServiceCore::UnsubscribeTemplateStatusChange(
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback)
{
    IAM_LOGI("Start");
    ENSURE_OR_RETURN_VAL(templateStatusCallback != nullptr, ResultCode::INVALID_PARAMETERS);
    ENSURE_OR_RETURN_VAL(subscriptionManager_ != nullptr, ResultCode::GENERAL_ERROR);

    subscriptionManager_->RemoveTemplateStatusCallback(templateStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode BaseServiceCore::SubscribeContinuousAuthStatusChange(
    const IpcSubscribeContinuousAuthStatusParam &subscribeContinuousAuthStatusParam,
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback)
{
    IAM_LOGI("Start");
    ENSURE_OR_RETURN_VAL(continuousAuthStatusCallback != nullptr, ResultCode::INVALID_PARAMETERS);
    ENSURE_OR_RETURN_VAL(subscriptionManager_ != nullptr, ResultCode::GENERAL_ERROR);

    if (subscribeContinuousAuthStatusParam.localUserId != GetUserIdManager().GetActiveUserId()) {
        IAM_LOGE("userId %{public}d is not the active user id %{public}d",
            subscribeContinuousAuthStatusParam.localUserId, GetUserIdManager().GetActiveUserId());
        return ResultCode::GENERAL_ERROR;
    }

    std::optional<TemplateId> subscriptionTemplateId = std::nullopt;
    if (subscribeContinuousAuthStatusParam.hasTemplateId) {
        HostCheckTemplateEnrolledInput checkInput { .templateId = subscribeContinuousAuthStatusParam.templateId };
        HostCheckTemplateEnrolledOutput checkOutput {};
        ResultCode ret = GetSecurityAgent().HostCheckTemplateEnrolled(checkInput, checkOutput);
        ENSURE_OR_RETURN_VAL(ret == ResultCode::SUCCESS, ResultCode::GENERAL_ERROR);
        if (!checkOutput.enrolled) {
            IAM_LOGE("templateId %{public}s not enrolled",
                GET_MASKED_NUM_CSTR(subscribeContinuousAuthStatusParam.templateId));
            return ResultCode::NOT_ENROLLED;
        }
        subscriptionTemplateId = subscribeContinuousAuthStatusParam.templateId;
    } else {
        subscriptionTemplateId = std::nullopt;
    }
    subscriptionManager_->AddContinuousAuthStatusCallback(subscribeContinuousAuthStatusParam.localUserId,
        subscriptionTemplateId, continuousAuthStatusCallback);

    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode BaseServiceCore::UnsubscribeContinuousAuthStatusChange(
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback)
{
    IAM_LOGI("Start");
    ENSURE_OR_RETURN_VAL(continuousAuthStatusCallback != nullptr, ResultCode::INVALID_PARAMETERS);
    ENSURE_OR_RETURN_VAL(subscriptionManager_ != nullptr, ResultCode::GENERAL_ERROR);

    subscriptionManager_->RemoveContinuousAuthStatusCallback(continuousAuthStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode BaseServiceCore::UpdateTemplateEnabledBusinessIds(uint64_t templateId,
    const std::vector<int32_t> &enabledBusinessIds)
{
    IAM_LOGI("Start");

    if (enabledBusinessIds.size() > MAX_ENABLED_BUSINESS_IDS) {
        IAM_LOGE("enabledBusinessIds size exceeds limit: %{public}zu > %{public}zu", enabledBusinessIds.size(),
            MAX_ENABLED_BUSINESS_IDS);
        return ResultCode::INVALID_PARAMETERS;
    }

    // Convert int32_t to BusinessId for internal APIs
    std::vector<BusinessId> businessIdEnums;
    businessIdEnums.reserve(enabledBusinessIds.size());
    for (const auto &id : enabledBusinessIds) {
        businessIdEnums.push_back(static_cast<BusinessId>(id));
    }

    // Validate business IDs against supported list
    for (const auto &businessId : businessIdEnums) {
        if (!IsValidBusinessId(businessId)) {
            IAM_LOGE("Invalid businessId:%{public}d", businessId);
            return ResultCode::INVALID_BUSINESS_ID;
        }
    }

    IAM_LOGI("enabledBusinessIds:%{public}s", GetVectorString(enabledBusinessIds).c_str());

    ResultCode ret =
        GetCompanionManager().UpdateCompanionEnabledBusinessIds(static_cast<TemplateId>(templateId), businessIdEnums);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("UpdateCompanionEnabledBusinessIds failed ret=%{public}d", ret);
        return ret;
    }

    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode BaseServiceCore::GetTemplateStatus(int32_t localUserId, std::vector<IpcTemplateStatus> &templateStatusArray)
{
    IAM_LOGI("Start");

    if (localUserId != GetUserIdManager().GetActiveUserId()) {
        IAM_LOGE("userId %{public}d is not the active user id %{public}d", localUserId,
            GetUserIdManager().GetActiveUserId());
        return ResultCode::GENERAL_ERROR;
    }

    std::vector<CompanionStatus> companionStatusList = GetCompanionManager().GetAllCompanionStatus();
    std::optional<SteadyTimeMs> manageSubscribeTime = GetCrossDeviceCommManager().GetManageSubscribeTime();

    for (const auto &status : companionStatusList) {
        if (status.hostUserId != localUserId) {
            IAM_LOGE("localUserId mismatch");
            continue;
        }

        IpcTemplateStatus ipcStatus {};
        ipcStatus.templateId = status.templateId;
        ipcStatus.isConfirmed = manageSubscribeTime.has_value() &&
            (status.companionDeviceStatus.lastSyncTimeMs >= manageSubscribeTime.value());
        ipcStatus.isValid = status.isValid;
        ipcStatus.localUserId = status.hostUserId;
        ipcStatus.addedTime = status.addedTime;
        ipcStatus.enabledBusinessIds.reserve(status.enabledBusinessIds.size());
        for (const auto &id : status.enabledBusinessIds) {
            ipcStatus.enabledBusinessIds.push_back(static_cast<int>(id));
        }

        IpcDeviceStatus ipcDeviceStatus {};
        ipcDeviceStatus.deviceKey.deviceIdType = static_cast<int32_t>(status.companionDeviceStatus.deviceKey.idType);
        ipcDeviceStatus.deviceKey.deviceId = status.companionDeviceStatus.deviceKey.deviceId;
        ipcDeviceStatus.deviceKey.deviceUserId = status.companionDeviceStatus.deviceKey.deviceUserId;
        ipcDeviceStatus.deviceUserName = status.companionDeviceStatus.deviceUserName;
        ipcDeviceStatus.deviceModelInfo = status.companionDeviceStatus.deviceModelInfo;
        ipcDeviceStatus.deviceName = status.companionDeviceStatus.deviceName;
        ipcDeviceStatus.isOnline = status.companionDeviceStatus.isOnline;
        ipcDeviceStatus.supportedBusinessIds.reserve(status.companionDeviceStatus.supportedBusinessIds.size());
        for (const auto &id : status.companionDeviceStatus.supportedBusinessIds) {
            ipcDeviceStatus.supportedBusinessIds.push_back(static_cast<int>(id));
        }
        ipcStatus.deviceStatus = ipcDeviceStatus;

        templateStatusArray.push_back(ipcStatus);
    }

    IAM_LOGI("End, get size:%{public}zu", templateStatusArray.size());
    return ResultCode::SUCCESS;
}

ResultCode BaseServiceCore::RegisterDeviceSelectCallback(uint32_t tokenId,
    const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback)
{
    IAM_LOGI("Start");
    ENSURE_OR_RETURN_VAL(deviceSelectCallback != nullptr, ResultCode::INVALID_PARAMETERS);

    if (!GetMiscManager().SetDeviceSelectCallback(tokenId, deviceSelectCallback)) {
        IAM_LOGE("failed to SetDeviceSelectCallback");
        return ResultCode::GENERAL_ERROR;
    }

    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode BaseServiceCore::UnregisterDeviceSelectCallback(uint32_t tokenId)
{
    IAM_LOGI("Start");
    GetMiscManager().ClearDeviceSelectCallback(tokenId);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode BaseServiceCore::RegisterPasscodePromptCallback(uint32_t tokenId,
    const sptr<IIpcPasscodePromptCallback> &passcodePromptCallback)
{
    IAM_LOGI("Start");
    ENSURE_OR_RETURN_VAL(passcodePromptCallback != nullptr, ResultCode::INVALID_PARAMETERS);

    if (!GetMiscManager().SetPasscodePromptCallback(tokenId, passcodePromptCallback)) {
        IAM_LOGE("failed to SetPasscodePromptCallback");
        return ResultCode::GENERAL_ERROR;
    }

    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode BaseServiceCore::UnregisterPasscodePromptCallback(uint32_t tokenId)
{
    IAM_LOGI("Start");
    GetMiscManager().ClearPasscodePromptCallback(tokenId);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

bool BaseServiceCore::CheckLocalUserIdValid(int32_t localUserId)
{
    IAM_LOGI("Start");
    bool isUserIdValid = GetUserIdManager().IsUserIdValid(localUserId);
    IAM_LOGI("End, isUserIdValid=%{public}d", isUserIdValid);
    return isUserIdValid;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
