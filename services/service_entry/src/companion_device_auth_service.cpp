/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "companion_device_auth_service.h"

#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <new>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "refbase.h"
#include "system_ability.h"
#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "access_token_kit.h"
#include "adapter_manager.h"
#include "base_service_core.h"
#include "base_service_initializer.h"
#include "common_defines.h"
#include "companion_manager_impl.h"
#include "cross_device_comm_manager_impl.h"
#include "event_manager_adapter_impl.h"
#include "fwk_comm_manager.h"
#include "host_binding_manager_impl.h"
#include "misc_manager_impl.h"
#include "sa_manager_adapter_impl.h"
#include "security_command_adapter_impl.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "subscription_manager.h"
#include "system_param_manager_impl.h"
#include "task_runner_manager.h"
#include "tokenid_kit.h"
#include "user_id_manager.h"
#include "xcollie_helper.h"

#include "driver_manager_adapter_impl.h"
#include "idm_adapter_impl.h"
#include "relative_timer.h"
#include "user_auth_adapter_impl.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_CDA_SERVICE

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
#ifndef ENABLE_STATIC_LIB
[[maybe_unused]] sptr<CompanionDeviceAuthService> GetServiceInstance()
{
    static sptr<CompanionDeviceAuthService> instance = []() {
        auto ptr = sptr<CompanionDeviceAuthService>::MakeSptr(
            []() -> std::shared_ptr<BaseServiceInitializer> { return BaseServiceInitializer::Create(); },
            [](const std::shared_ptr<SubscriptionManager> &subscriptionManager,
                const std::vector<BusinessId> &supportedBusinessIds) -> std::shared_ptr<BaseServiceCore> {
                return BaseServiceCore::Create(subscriptionManager, supportedBusinessIds);
            });
        ptr->SetWeakPtr(ptr);
        return ptr;
    }();
    return instance;
}

#ifndef ENABLE_TEST
[[maybe_unused]] const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(GetServiceInstance().GetRefPtr());
#endif // ENABLE_TEST
#endif // ENABLE_STATIC_LIB
} // namespace

CompanionDeviceAuthService::CompanionDeviceAuthService(BaseServiceInitializerCreator initializerCreator,
    BaseServiceCoreCreator coreCreator)
    : SystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, true),
      initializerCreator_(std::move(initializerCreator)),
      coreCreator_(std::move(coreCreator))
{
}

void CompanionDeviceAuthService::SetWeakPtr(const wptr<IRemoteObject> &weakSelf)
{
    weakSelf_ = weakSelf;
}

bool CompanionDeviceAuthService::CheckPermission(const std::string &permission, int32_t &companionDeviceAuthResult)
{
    if (!AccessTokenUtil::CheckPermission(*this, permission)) {
        IAM_LOGE("check permission %{public}s failed", permission.c_str());
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::CHECK_PERMISSION_FAILED);
        return false;
    }
    if (!AccessTokenUtil::CheckSystemPermission(*this)) {
        IAM_LOGE("check is system app permission failed");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::CHECK_SYSTEM_PERMISSION_FAILED);
        return false;
    }
    return true;
}

void CompanionDeviceAuthService::OnStart()
{
    IAM_LOGI("Start");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (baseServiceInitializer_ != nullptr || core_ != nullptr) {
            IAM_LOGE("base service initializer or inner service already created");
            return;
        }
    }

    auto resultOpt = RunOnResidentSync(
        [initializerCreator = initializerCreator_, coreCreator = coreCreator_]()
            -> std::pair<std::shared_ptr<BaseServiceInitializer>, std::shared_ptr<BaseServiceCore>> {
            auto baseServiceInitializer = initializerCreator();
            ENSURE_OR_RETURN_VAL(baseServiceInitializer != nullptr, std::make_pair(nullptr, nullptr));

            auto core = coreCreator(baseServiceInitializer->GetSubscriptionManager(),
                baseServiceInitializer->GetSupportedBusinessIds());
            ENSURE_OR_RETURN_VAL(core != nullptr, std::make_pair(nullptr, nullptr));
            IAM_LOGI("created inner service");

            RelativeTimer::GetInstance().PostTask(
                []() { GetSystemParamManager().SetParam(CDA_IS_FUNCTION_READY_KEY, TRUE_STR); }, SET_PARAM_DELAY_MS);
            return std::make_pair(baseServiceInitializer, core);
        },
        MAX_ON_START_WAIT_TIME_SEC);
    if (!resultOpt.has_value()) {
        IAM_LOGE("failed to create service - timeout");
        return;
    }

    auto [baseServiceInitializer, core] = resultOpt.value();
    if (baseServiceInitializer == nullptr || core == nullptr) {
        IAM_LOGE("failed to create base service initializer or inner service");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        baseServiceInitializer_ = baseServiceInitializer;
        core_ = core;
    }

    auto sharedPtr = weakSelf_.promote();
    ENSURE_OR_RETURN(sharedPtr != nullptr);
    if (!Publish(sharedPtr)) {
        IAM_LOGE("fail to publish companion device auth service");
        std::lock_guard<std::mutex> lock(mutex_);
        core_.reset();
        baseServiceInitializer_.reset();
        return;
    }
    IAM_LOGI("End");
}

void CompanionDeviceAuthService::OnStop()
{
    IAM_LOGE("OnStop called unexpectedly - this service should remain resident");
}

ErrCode CompanionDeviceAuthService::SubscribeAvailableDeviceStatus(int32_t localUserId,
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start, localUserId:%{public}d", localUserId);
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(USE_USER_IDM_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([core, localUserId, deviceStatusCallback]() {
        return core->SubscribeAvailableDeviceStatus(localUserId, deviceStatusCallback);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("SubscribeAvailableDeviceStatus timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnsubscribeAvailableDeviceStatus(
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(USE_USER_IDM_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync(
        [core, deviceStatusCallback]() { return core->UnsubscribeAvailableDeviceStatus(deviceStatusCallback); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnsubscribeAvailableDeviceStatus timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::SubscribeTemplateStatusChange(int32_t localUserId,
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start, localUserId:%{public}d", localUserId);
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(USE_USER_IDM_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([core, localUserId, templateStatusCallback]() {
        return core->SubscribeTemplateStatusChange(localUserId, templateStatusCallback);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("SubscribeTemplateStatusChange timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnsubscribeTemplateStatusChange(
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(USE_USER_IDM_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync(
        [core, templateStatusCallback]() { return core->UnsubscribeTemplateStatusChange(templateStatusCallback); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnsubscribeTemplateStatusChange timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::SubscribeContinuousAuthStatusChange(
    const IpcSubscribeContinuousAuthStatusParam &subscribeContinuousAuthStatusParam,
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start, localUserId:%{public}d, hasTemplateId:%{public}d, templateId:%{public}s",
        subscribeContinuousAuthStatusParam.localUserId, subscribeContinuousAuthStatusParam.hasTemplateId,
        GET_MASKED_NUM_CSTR(subscribeContinuousAuthStatusParam.templateId));
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(USE_USER_IDM_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([core, subscribeContinuousAuthStatusParam, continuousAuthStatusCallback]() {
        return core->SubscribeContinuousAuthStatusChange(subscribeContinuousAuthStatusParam,
            continuousAuthStatusCallback);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("SubscribeContinuousAuthStatusChange timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnsubscribeContinuousAuthStatusChange(
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(USE_USER_IDM_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([core, continuousAuthStatusCallback]() {
        return core->UnsubscribeContinuousAuthStatusChange(continuousAuthStatusCallback);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnsubscribeContinuousAuthStatusChange timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UpdateTemplateEnabledBusinessIds(uint64_t templateId,
    const std::vector<int32_t> &enabledBusinessIds, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start, templateId:%{public}s, enabledBusinessIds:%{public}s", GET_MASKED_NUM_CSTR(templateId),
        GetVectorString(enabledBusinessIds).c_str());
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(USE_USER_IDM_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([core, templateId, enabledBusinessIds]() {
        return core->UpdateTemplateEnabledBusinessIds(templateId, enabledBusinessIds);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UpdateTemplateEnabledBusinessIds timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::GetTemplateStatus(int32_t localUserId,
    std::vector<IpcTemplateStatus> &templateStatusArray, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start, localUserId:%{public}d", localUserId);
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(USE_USER_IDM_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    auto resultPair = RunOnResidentSync([core, localUserId]() {
        std::vector<IpcTemplateStatus> array;
        ResultCode result = core->GetTemplateStatus(localUserId, array);
        return std::make_pair(result, std::move(array));
    });
    if (!resultPair.has_value()) {
        IAM_LOGE("GetTemplateStatus timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultPair->first);
    templateStatusArray = std::move(resultPair->second);
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::RegisterDeviceSelectCallback(
    const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(USE_USER_IDM_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    uint32_t tokenId = AccessTokenUtil::GetAccessTokenId(*this);
    ENSURE_OR_RETURN_VAL(tokenId != 0, ResultCode::GENERAL_ERROR);
    auto resultOpt = RunOnResidentSync([core, deviceSelectCallback, tokenId]() {
        return core->RegisterDeviceSelectCallback(tokenId, deviceSelectCallback);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("RegisterDeviceSelectCallback timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnregisterDeviceSelectCallback(int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(USE_USER_IDM_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    uint32_t tokenId = AccessTokenUtil::GetAccessTokenId(*this);
    ENSURE_OR_RETURN_VAL(tokenId != 0, ResultCode::GENERAL_ERROR);
    auto resultOpt = RunOnResidentSync([core, tokenId]() { return core->UnregisterDeviceSelectCallback(tokenId); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnregisterDeviceSelectCallback timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::RegisterPasscodePromptCallback(
    const sptr<IIpcPasscodePromptCallback> &passcodePromptCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    uint32_t tokenId = AccessTokenUtil::GetAccessTokenId(*this);
    ENSURE_OR_RETURN_VAL(tokenId != 0, ResultCode::GENERAL_ERROR);
    auto resultOpt = RunOnResidentSync([core, passcodePromptCallback, tokenId]() {
        return core->RegisterPasscodePromptCallback(tokenId, passcodePromptCallback);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("RegisterPasscodePromptCallback timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnregisterPasscodePromptCallback(int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    uint32_t tokenId = AccessTokenUtil::GetAccessTokenId(*this);
    ENSURE_OR_RETURN_VAL(tokenId != 0, ResultCode::GENERAL_ERROR);
    auto resultOpt = RunOnResidentSync([core, tokenId]() { return core->UnregisterPasscodePromptCallback(tokenId); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnregisterPasscodePromptCallback timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::CheckLocalUserIdValid(int32_t localUserId, bool &isUserIdValid,
    int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start, localUserId:%{public}d", localUserId);
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(USE_USER_IDM_PERMISSION, companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> core;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        core = core_;
    }
    ENSURE_OR_RETURN_VAL(core != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([core, localUserId]() { return core->CheckLocalUserIdValid(localUserId); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("CheckLocalUserIdValid timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::SUCCESS);
    isUserIdValid = resultOpt.value();
    IAM_LOGI("End");
    return ERR_OK;
}

int32_t CompanionDeviceAuthService::CallbackEnter(uint32_t code)
{
    IAM_LOGI("CallbackEnter, code:%{public}u", code);
    return 0;
}

int32_t CompanionDeviceAuthService::CallbackExit(uint32_t code, int32_t result)
{
    IAM_LOGI("CallbackExit, code:%{public}u, result:%{public}d", code, result);
    return 0;
}

template <typename Func>
std::optional<typename std::invoke_result<Func>::type> CompanionDeviceAuthService::RunOnResidentSync(Func &&func,
    uint32_t timeoutSec)
{
    using Ret = typename std::invoke_result<Func>::type;

    if (TaskRunnerManager::GetInstance().RunningOnDefaultTaskRunner()) {
        IAM_LOGI("running on resident task runner");
        return func();
    }

    auto promise = std::make_shared<std::promise<Ret>>();
    ENSURE_OR_RETURN_VAL(promise != nullptr, std::nullopt);
    auto future = promise->get_future();
    auto cancelled = std::make_shared<std::atomic<bool>>(false);
    ENSURE_OR_RETURN_VAL(cancelled != nullptr, std::nullopt);

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [task = std::forward<Func>(func), promise, cancelled]() mutable {
            if (cancelled->load()) {
                IAM_LOGI("RunOnResidentSync task cancelled before execution");
                return;
            }
            try {
                promise->set_value(task());
            } catch (...) {
                try {
                    promise->set_exception(std::current_exception());
                } catch (...) {
                    IAM_LOGE("RunOnResidentSync set_exception failed");
                }
            }
        });

    auto status = future.wait_for(std::chrono::seconds(timeoutSec));
    if (status != std::future_status::ready) {
        IAM_LOGE("RunOnResidentSync timeout - task not completed in %{public}u second, status: %{public}d", timeoutSec,
            static_cast<int32_t>(status));
        cancelled->store(true);
        return std::nullopt;
    }

    return future.get();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
