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
#include <functional>
#include <map>
#include <memory>
#include <new>
#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "refbase.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"

#include "common_defines.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#include "active_user_id_manager.h"
#include "companion_manager_impl.h"
#include "cross_device_comm_manager_impl.h"
#include "fwk_comm_manager.h"
#include "host_binding_manager_impl.h"
#include "icross_device_channel.h"
#include "incoming_message_handler_registry.h"
#include "misc_manager_impl.h"
#include "request_factory_impl.h"
#include "request_manager_impl.h"
#include "security_agent_imp.h"
#include "singleton_manager.h"
#include "soft_bus_channel.h"
#include "subscription_manager.h"
#include "system_param_manager_impl.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
[[maybe_unused]] const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(CompanionDeviceAuthService::GetInstance().GetRefPtr());

static uint32_t GetAccessTokenId(IPCObjectStub &stub)
{
    uint32_t tokenId = stub.GetFirstTokenID();
    IAM_LOGD("get first caller tokenId: %{public}s", GET_MASKED_NUM_STRING(tokenId).c_str());
    if (tokenId == 0) {
        tokenId = stub.GetCallingTokenID();
        IAM_LOGD("no first caller, get direct caller tokenId: %{public}s", GET_MASKED_NUM_STRING(tokenId).c_str());
    }
    return tokenId;
}
} // namespace

class CompanionDeviceAuthService::CompanionDeviceAuthServiceInner : public NoCopyable {
public:
    static std::shared_ptr<CompanionDeviceAuthServiceInner> Create();

    int32_t SubscribeAvailableDeviceStatus(int32_t localUserId,
        const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback);
    int32_t UnsubscribeAvailableDeviceStatus(const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback);
    int32_t SubscribeTemplateStatusChange(int32_t localUserId,
        const sptr<IIpcTemplateStatusCallback> &templateStatusCallback);
    int32_t UnsubscribeTemplateStatusChange(const sptr<IIpcTemplateStatusCallback> &templateStatusCallback);
    int32_t SubscribeContinuousAuthStatusChange(
        const IpcSubscribeContinuousAuthStatusParam &subscribeContinuousAuthStatusParam,
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback);
    int32_t UnsubscribeContinuousAuthStatusChange(
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback);
    int32_t UpdateTemplateEnabledBusinessIds(uint64_t templateId, const std::vector<int32_t> &enabledBusinessIds);
    int32_t GetTemplateStatus(std::vector<IpcTemplateStatus> &templateStatusArray);
    int32_t RegisterDeviceSelectCallback(uint32_t tokenId, const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback);
    int32_t UnregisterDeviceSelectCallback(uint32_t tokenId);

private:
    static bool SetBasicManager();

    explicit CompanionDeviceAuthServiceInner(std::shared_ptr<SubscriptionManager> subscriptionManager)
        : subscriptionManagerHolder_(std::move(subscriptionManager)),
          subscriptionManager_(*subscriptionManagerHolder_)
    {
    }

    std::shared_ptr<SubscriptionManager> subscriptionManagerHolder_;
    SubscriptionManager &subscriptionManager_;
};

using CompanionDeviceAuthServiceInner = CompanionDeviceAuthService::CompanionDeviceAuthServiceInner;

bool CompanionDeviceAuthServiceInner::SetBasicManager()
{
    auto &singletonManager = SingletonManager::GetInstance();

    auto requestManager = RequestManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(requestManager != nullptr, false);
    singletonManager.SetRequestManager(requestManager);

    auto requestFactory = RequestFactoryImpl::Create();
    ENSURE_OR_RETURN_VAL(requestFactory != nullptr, false);
    singletonManager.SetRequestFactory(requestFactory);

    auto miscManager = MiscManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(miscManager != nullptr, false);
    singletonManager.SetMiscManager(miscManager);

    auto systemParamManager = SystemParamManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(systemParamManager != nullptr, false);
    singletonManager.SetSystemParamManager(systemParamManager);

    auto activeUserIdManager = IActiveUserIdManager::Create();
    ENSURE_OR_RETURN_VAL(activeUserIdManager != nullptr, false);
    singletonManager.SetActiveUserIdManager(activeUserIdManager);

    auto securityAgent = SecurityAgentImpl::Create();
    ENSURE_OR_RETURN_VAL(securityAgent != nullptr, false);
    singletonManager.SetSecurityAgent(securityAgent);

    return true;
}

std::shared_ptr<CompanionDeviceAuthServiceInner> CompanionDeviceAuthServiceInner::Create()
{
    IAM_LOGI("Start");
    bool setBasicManagerRet = SetBasicManager();
    ENSURE_OR_RETURN_VAL(setBasicManagerRet, nullptr);

    auto &singletonManager = SingletonManager::GetInstance();

    auto registry = IncomingMessageHandlerRegistry::Create();
    ENSURE_OR_RETURN_VAL(registry != nullptr, nullptr);
    singletonManager.SetIncomingMessageHandlerRegistry(registry);

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    auto softBusChannel = SoftBusChannel::Create();
    if (softBusChannel != nullptr) {
        channels.push_back(softBusChannel);
    }

    auto crossDeviceCommManager = CrossDeviceCommManagerImpl::Create(channels);
    ENSURE_OR_RETURN_VAL(crossDeviceCommManager != nullptr, nullptr);
    singletonManager.SetCrossDeviceCommManager(crossDeviceCommManager);

    auto companionManager = CompanionManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(companionManager != nullptr, nullptr);
    singletonManager.SetCompanionManager(companionManager);

    auto hostBindingManager = HostBindingManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(hostBindingManager != nullptr, nullptr);
    singletonManager.SetHostBindingManager(hostBindingManager);

    bool registerSuccess = registry->RegisterHandlers();
    ENSURE_OR_RETURN_VAL(registerSuccess, nullptr);

    bool startSuccess = crossDeviceCommManager->Start();
    ENSURE_OR_RETURN_VAL(startSuccess, nullptr);

    auto subscriptionManager = std::make_shared<SubscriptionManager>();

    if (FwkCommManager::Create() == nullptr) {
        IAM_LOGE("failed to create FwkCommManager");
    }
    auto inner = std::shared_ptr<CompanionDeviceAuthServiceInner>(
        new (std::nothrow) CompanionDeviceAuthServiceInner(subscriptionManager));
    ENSURE_OR_RETURN_VAL(inner != nullptr, nullptr);
    IAM_LOGI("End");
    return inner;
}

int32_t CompanionDeviceAuthServiceInner::SubscribeAvailableDeviceStatus(int32_t localUserId,
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback)
{
    IAM_LOGI("Start");
    if (deviceStatusCallback == nullptr) {
        IAM_LOGE("deviceStatusCallback is nullptr");
        return static_cast<int32_t>(ResultCode::INVALID_PARAMETERS);
    }

    subscriptionManager_.AddAvailableDeviceStatusCallback(localUserId, deviceStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

int32_t CompanionDeviceAuthServiceInner::UnsubscribeAvailableDeviceStatus(
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback)
{
    IAM_LOGI("Start");
    if (deviceStatusCallback == nullptr) {
        IAM_LOGE("deviceStatusCallback is nullptr");
        return static_cast<int32_t>(ResultCode::INVALID_PARAMETERS);
    }

    subscriptionManager_.RemoveAvailableDeviceStatusCallback(deviceStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

int32_t CompanionDeviceAuthServiceInner::SubscribeTemplateStatusChange(int32_t localUserId,
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback)
{
    IAM_LOGI("Start");
    if (templateStatusCallback == nullptr) {
        IAM_LOGE("templateStatusCallback is nullptr");
        return static_cast<int32_t>(ResultCode::INVALID_PARAMETERS);
    }

    subscriptionManager_.AddTemplateStatusCallback(localUserId, templateStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

int32_t CompanionDeviceAuthServiceInner::UnsubscribeTemplateStatusChange(
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback)
{
    IAM_LOGI("Start");
    if (templateStatusCallback == nullptr) {
        IAM_LOGE("templateStatusCallback is nullptr");
        return static_cast<int32_t>(ResultCode::INVALID_PARAMETERS);
    }

    subscriptionManager_.RemoveTemplateStatusCallback(templateStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

int32_t CompanionDeviceAuthServiceInner::SubscribeContinuousAuthStatusChange(
    const IpcSubscribeContinuousAuthStatusParam &subscribeContinuousAuthStatusParam,
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback)
{
    IAM_LOGI("Start");
    if (continuousAuthStatusCallback == nullptr) {
        IAM_LOGE("continuousAuthStatusCallback is nullptr");
        return static_cast<int32_t>(ResultCode::INVALID_PARAMETERS);
    }

    if (subscribeContinuousAuthStatusParam.hasTemplateId) {
        IAM_LOGI("hasTemplateId");
        subscriptionManager_.AddContinuousAuthStatusCallback(subscribeContinuousAuthStatusParam.localUserId,
            subscribeContinuousAuthStatusParam.templateId, continuousAuthStatusCallback);
    } else {
        IAM_LOGI("not hasTemplateId");
        subscriptionManager_.AddContinuousAuthStatusCallback(subscribeContinuousAuthStatusParam.localUserId,
            std::nullopt, continuousAuthStatusCallback);
    }

    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

int32_t CompanionDeviceAuthServiceInner::UnsubscribeContinuousAuthStatusChange(
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback)
{
    IAM_LOGI("Start");
    if (continuousAuthStatusCallback == nullptr) {
        IAM_LOGE("continuousAuthStatusCallback is nullptr");
        return static_cast<int32_t>(ResultCode::INVALID_PARAMETERS);
    }

    subscriptionManager_.RemoveContinuousAuthStatusCallback(continuousAuthStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

int32_t CompanionDeviceAuthServiceInner::UpdateTemplateEnabledBusinessIds(uint64_t templateId,
    const std::vector<int32_t> &enabledBusinessIds)
{
    IAM_LOGI("Start");
    ResultCode ret = GetCompanionManager().UpdateCompanionEnabledBusinessIds(static_cast<TemplateId>(templateId),
        enabledBusinessIds);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("UpdateCompanionEnabledBusinessIds failed ret=%{public}d", ret);
        return static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    }

    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

int32_t CompanionDeviceAuthServiceInner::GetTemplateStatus(std::vector<IpcTemplateStatus> &templateStatusArray)
{
    IAM_LOGI("Start");
    std::vector<CompanionStatus> companionStatusList = GetCompanionManager().GetAllCompanionStatus();
    std::optional<int64_t> manageSubscribeTime = GetCrossDeviceCommManager().GetManageSubscribeTime();

    for (const auto &status : companionStatusList) {
        IpcTemplateStatus ipcStatus;
        ipcStatus.templateId = status.templateId;
        ipcStatus.isConfirmed =
            manageSubscribeTime.has_value() && (status.lastCheckTime >= manageSubscribeTime.value());
        ipcStatus.isValid = status.isValid;
        ipcStatus.localUserId = status.hostUserId;
        ipcStatus.addedTime = status.addedTime;
        ipcStatus.enabledBusinessIds = status.enabledBusinessIds;

        IpcDeviceStatus ipcDeviceStatus;
        ipcDeviceStatus.deviceKey.deviceIdType = static_cast<int32_t>(status.companionDeviceStatus.deviceKey.idType);
        ipcDeviceStatus.deviceKey.deviceId = status.companionDeviceStatus.deviceKey.deviceId;
        ipcDeviceStatus.deviceKey.deviceUserId = status.companionDeviceStatus.deviceKey.deviceUserId;
        ipcDeviceStatus.deviceUserName = status.companionDeviceStatus.deviceUserName;
        ipcDeviceStatus.deviceModelInfo = status.companionDeviceStatus.deviceModelInfo;
        ipcDeviceStatus.deviceName = status.companionDeviceStatus.deviceName;
        ipcDeviceStatus.isOnline = status.companionDeviceStatus.isOnline;
        ipcDeviceStatus.supportedBusinessIds = status.companionDeviceStatus.supportedBusinessIds;
        ipcStatus.deviceStatus = ipcDeviceStatus;

        templateStatusArray.push_back(ipcStatus);
    }

    IAM_LOGI("End, get size:%{public}zu", templateStatusArray.size());
    return ResultCode::SUCCESS;
}

int32_t CompanionDeviceAuthServiceInner::RegisterDeviceSelectCallback(uint32_t tokenId,
    const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback)
{
    IAM_LOGI("Start");
    if (deviceSelectCallback == nullptr) {
        IAM_LOGE("deviceSelectCallback is nullptr");
        return static_cast<int32_t>(ResultCode::INVALID_PARAMETERS);
    }

    if (!GetMiscManager().SetDeviceSelectCallback(tokenId, deviceSelectCallback)) {
        IAM_LOGE("failed to SetDeviceSelectCallback");
        return static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    }

    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

int32_t CompanionDeviceAuthServiceInner::UnregisterDeviceSelectCallback(uint32_t tokenId)
{
    IAM_LOGI("Start");
    GetMiscManager().ClearDeviceSelectCallback(tokenId);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

sptr<CompanionDeviceAuthService> CompanionDeviceAuthService::GetInstance()
{
    static sptr<CompanionDeviceAuthService> instance = sptr<CompanionDeviceAuthService>::MakeSptr();
    return instance;
}

CompanionDeviceAuthService::CompanionDeviceAuthService() : SystemAbility(COMPANION_DEVICE_AUTH_SA_ID, true)
{
}

void CompanionDeviceAuthService::OnStart()
{
    IAM_LOGI("Start");
    if (!Publish(CompanionDeviceAuthService::GetInstance())) {
        IAM_LOGE("fail to publish companion device auth service");
        return;
    }

    sptr<CompanionDeviceAuthService> self = this;
    TaskRunnerManager::GetInstance().PostTaskOnResident([self]() {
        auto inner = CompanionDeviceAuthServiceInner::Create();
        if (inner == nullptr) {
            IAM_LOGE("failed to create inner");
            return;
        }
        self->inner_ = inner;
    });
    IAM_LOGI("End");
}

void CompanionDeviceAuthService::OnStop()
{
}

ErrCode CompanionDeviceAuthService::SubscribeAvailableDeviceStatus(int32_t localUserId,
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto callbackCopy = deviceStatusCallback;
    auto resultOpt = RunOnResidentSync([inner, localUserId, callbackCopy]() {
        return inner->SubscribeAvailableDeviceStatus(localUserId, callbackCopy);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("SubscribeAvailableDeviceStatus timeout");
        return ERR_INVALID_VALUE;
    }
    companionDeviceAuthResult = resultOpt.value();
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnsubscribeAvailableDeviceStatus(
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto callbackCopy = deviceStatusCallback;
    auto resultOpt =
        RunOnResidentSync([inner, callbackCopy]() { return inner->UnsubscribeAvailableDeviceStatus(callbackCopy); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnsubscribeAvailableDeviceStatus timeout");
        return ERR_INVALID_VALUE;
    }
    companionDeviceAuthResult = resultOpt.value();
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::SubscribeTemplateStatusChange(int32_t localUserId,
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto callbackCopy = templateStatusCallback;
    auto resultOpt = RunOnResidentSync([inner, localUserId, callbackCopy]() {
        return inner->SubscribeTemplateStatusChange(localUserId, callbackCopy);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("SubscribeTemplateStatusChange timeout");
        return ERR_INVALID_VALUE;
    }
    companionDeviceAuthResult = resultOpt.value();
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnsubscribeTemplateStatusChange(
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto callbackCopy = templateStatusCallback;
    auto resultOpt =
        RunOnResidentSync([inner, callbackCopy]() { return inner->UnsubscribeTemplateStatusChange(callbackCopy); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnsubscribeTemplateStatusChange timeout");
        return ERR_INVALID_VALUE;
    }
    companionDeviceAuthResult = resultOpt.value();
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::SubscribeContinuousAuthStatusChange(
    const IpcSubscribeContinuousAuthStatusParam &subscribeContinuousAuthStatusParam,
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto paramCopy = subscribeContinuousAuthStatusParam;
    auto callbackCopy = continuousAuthStatusCallback;
    auto resultOpt = RunOnResidentSync([inner, paramCopy, callbackCopy]() {
        return inner->SubscribeContinuousAuthStatusChange(paramCopy, callbackCopy);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("SubscribeContinuousAuthStatusChange timeout");
        return ERR_INVALID_VALUE;
    }
    companionDeviceAuthResult = resultOpt.value();
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnsubscribeContinuousAuthStatusChange(
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto callbackCopy = continuousAuthStatusCallback;
    auto resultOpt = RunOnResidentSync(
        [inner, callbackCopy]() { return inner->UnsubscribeContinuousAuthStatusChange(callbackCopy); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnsubscribeContinuousAuthStatusChange timeout");
        return ERR_INVALID_VALUE;
    }
    companionDeviceAuthResult = resultOpt.value();
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UpdateTemplateEnabledBusinessIds(uint64_t templateId,
    const std::vector<int32_t> &enabledBusinessIds, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto enabledIdsCopy = enabledBusinessIds;
    auto resultOpt = RunOnResidentSync([inner, templateId, enabledIdsCopy]() {
        return inner->UpdateTemplateEnabledBusinessIds(templateId, enabledIdsCopy);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UpdateTemplateEnabledBusinessIds timeout");
        return ERR_INVALID_VALUE;
    }
    companionDeviceAuthResult = resultOpt.value();
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::GetTemplateStatus(std::vector<IpcTemplateStatus> &templateStatusArray,
    int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultPair = RunOnResidentSync([inner]() {
        std::vector<IpcTemplateStatus> array;
        int32_t result = inner->GetTemplateStatus(array);
        return std::make_pair(result, std::move(array));
    });
    if (!resultPair.has_value()) {
        IAM_LOGE("GetTemplateStatus timeout");
        return ERR_INVALID_VALUE;
    }
    companionDeviceAuthResult = resultPair->first;
    templateStatusArray = std::move(resultPair->second);
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::RegisterDeviceSelectCallback(
    const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    uint32_t tokenId = GetAccessTokenId(*this);
    auto callbackCopy = deviceSelectCallback;
    auto resultOpt = RunOnResidentSync(
        [inner, callbackCopy, tokenId]() { return inner->RegisterDeviceSelectCallback(tokenId, callbackCopy); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("RegisterDeviceSelectCallback timeout");
        return ERR_INVALID_VALUE;
    }
    companionDeviceAuthResult = resultOpt.value();
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnregisterDeviceSelectCallback(int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    uint32_t tokenId = GetAccessTokenId(*this);
    auto resultOpt = RunOnResidentSync([inner, tokenId]() { return inner->UnregisterDeviceSelectCallback(tokenId); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnregisterDeviceSelectCallback timeout");
        return ERR_INVALID_VALUE;
    }
    companionDeviceAuthResult = resultOpt.value();
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
std::optional<typename std::invoke_result<Func>::type> CompanionDeviceAuthService::RunOnResidentSync(Func &&func)
{
    using Ret = typename std::invoke_result<Func>::type;
    auto promise = std::make_shared<std::promise<Ret>>();
    auto future = promise->get_future();

    TaskRunnerManager::GetInstance().PostTaskOnResident([task = std::forward<Func>(func), promise]() mutable {
        try {
            promise->set_value(task());
        } catch (const std::future_error &e) {
            IAM_LOGE("RunOnResidentSync promise set_value error: %{public}s", e.what());
        }
    });

    if (future.wait_for(std::chrono::seconds(MAX_SYNC_WAIT_TIME_SEC)) != std::future_status::ready) {
        IAM_LOGE("RunOnResidentSync timeout - task not completed in 1 second");
        return std::nullopt;
    }

    return future.get();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
