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
#include <map>
#include <memory>
#include <mutex>
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

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "access_token_kit_adapter_impl.h"
#include "adapter_manager.h"
#include "common_defines.h"
#include "companion_manager_impl.h"
#include "cross_device_comm_manager_impl.h"
#include "event_manager_adapter_impl.h"
#include "fwk_comm_manager.h"
#include "host_binding_manager_impl.h"
#include "icross_device_channel.h"
#include "incoming_message_handler_registry.h"
#include "misc_manager_impl.h"
#include "request_factory_impl.h"
#include "request_manager_impl.h"
#include "sa_manager_adapter_impl.h"
#include "security_agent_imp.h"
#include "security_command_adapter_impl.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "subscription_manager.h"
#include "system_param_manager_impl.h"
#include "task_runner_manager.h"
#include "time_keeper_impl.h"
#include "tokenid_kit.h"
#include "user_id_manager.h"
#include "xcollie_helper.h"

#ifdef HAS_USER_AUTH_FRAMEWORK
#include "driver_manager_adapter_impl.h"
#include "idm_adapter_impl.h"
#include "user_auth_adapter_impl.h"
#endif

#ifdef HAS_SOFT_BUS_CHANNEL
#include "soft_bus_channel.h"
#endif

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
#ifndef ENABLE_TEST
[[maybe_unused]] const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(CompanionDeviceAuthService::GetInstance().GetRefPtr());
#endif // ENABLE_TEST
} // namespace

class CompanionDeviceAuthService::CompanionDeviceAuthServiceInner : public NoCopyable {
public:
    static std::shared_ptr<CompanionDeviceAuthServiceInner> Create();

    ResultCode SubscribeAvailableDeviceStatus(int32_t localUserId,
        const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback);
    ResultCode UnsubscribeAvailableDeviceStatus(const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback);
    ResultCode SubscribeTemplateStatusChange(int32_t localUserId,
        const sptr<IIpcTemplateStatusCallback> &templateStatusCallback);
    ResultCode UnsubscribeTemplateStatusChange(const sptr<IIpcTemplateStatusCallback> &templateStatusCallback);
    ResultCode SubscribeContinuousAuthStatusChange(
        const IpcSubscribeContinuousAuthStatusParam &subscribeContinuousAuthStatusParam,
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback);
    ResultCode UnsubscribeContinuousAuthStatusChange(
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback);
    ResultCode UpdateTemplateEnabledBusinessIds(uint64_t templateId, const std::vector<int32_t> &enabledBusinessIds);
    ResultCode GetTemplateStatus(int32_t localUserId, std::vector<IpcTemplateStatus> &templateStatusArray);
    ResultCode RegisterDeviceSelectCallback(uint32_t tokenId,
        const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback);
    ResultCode UnregisterDeviceSelectCallback(uint32_t tokenId);
    bool CheckLocalUserIdValid(int32_t localUserId);

private:
    static bool CreateStep1();
    static std::shared_ptr<IncomingMessageHandlerRegistry> CreateStep2();
    static std::shared_ptr<CompanionDeviceAuthServiceInner> CreateStep3(
        const std::shared_ptr<IncomingMessageHandlerRegistry> &registry);

    explicit CompanionDeviceAuthServiceInner(std::shared_ptr<SubscriptionManager> subscriptionManager)
        : subscriptionManagerHolder_(std::move(subscriptionManager)),
          subscriptionManager_(*subscriptionManagerHolder_)
    {
    }

    std::shared_ptr<SubscriptionManager> subscriptionManagerHolder_;
    SubscriptionManager &subscriptionManager_;
};

using CompanionDeviceAuthServiceInner = CompanionDeviceAuthService::CompanionDeviceAuthServiceInner;

std::shared_ptr<CompanionDeviceAuthServiceInner> CompanionDeviceAuthServiceInner::Create()
{
    IAM_LOGI("Start");

    if (!CreateStep1()) {
        IAM_LOGE("failed to execute CreateStep1");
        return nullptr;
    }

    auto registry = CreateStep2();
    if (registry == nullptr) {
        IAM_LOGE("failed to execute CreateStep2");
        return nullptr;
    }

    return CreateStep3(registry);
}

bool CompanionDeviceAuthServiceInner::CreateStep1()
{
    auto &adapterManager = AdapterManager::GetInstance();

    // Initialize external adapters in AdapterManager
    auto timeKeeper = TimeKeeperImpl::Create();
    ENSURE_OR_RETURN_VAL(timeKeeper != nullptr, false);
    adapterManager.SetTimeKeeper(timeKeeper);

    auto accessTokenKitAdapter = std::make_shared<AccessTokenKitAdapterImpl>();
    adapterManager.SetAccessTokenKitAdapter(accessTokenKitAdapter);

    auto eventManagerAdapter = std::make_shared<EventManagerAdapterImpl>();
    adapterManager.SetEventManagerAdapter(eventManagerAdapter);

    auto saManagerAdapter = std::make_shared<SaManagerAdapterImpl>();
    adapterManager.SetSaManagerAdapter(saManagerAdapter);

    auto securityCommandAdapter = SecurityCommandAdapterImpl::Create();
    ENSURE_OR_RETURN_VAL(securityCommandAdapter != nullptr, false);
    adapterManager.SetSecurityCommandAdapter(securityCommandAdapter);

    auto systemParamManager = SystemParamManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(systemParamManager != nullptr, false);
    adapterManager.SetSystemParamManager(systemParamManager);

    auto userIdManager = IUserIdManager::Create();
    ENSURE_OR_RETURN_VAL(userIdManager != nullptr, false);
    adapterManager.SetUserIdManager(userIdManager);

#ifdef HAS_USER_AUTH_FRAMEWORK
    auto userAuthAdapter = std::make_shared<UserAuthAdapterImpl>();
    adapterManager.SetUserAuthAdapter(userAuthAdapter);

    auto driverManagerAdapter = std::make_shared<DriverManagerAdapterImpl>();
    adapterManager.SetDriverManagerAdapter(driverManagerAdapter);

    auto idmAdapter = IdmAdapterImpl::Create();
    ENSURE_OR_RETURN_VAL(idmAdapter != nullptr, false);
    adapterManager.SetIdmAdapter(idmAdapter);
#endif

    return true;
}

std::shared_ptr<IncomingMessageHandlerRegistry> CompanionDeviceAuthServiceInner::CreateStep2()
{
    auto &singletonManager = SingletonManager::GetInstance();

    // Initialize internal singletons in SingletonManager
    auto requestManager = RequestManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(requestManager != nullptr, nullptr);
    singletonManager.SetRequestManager(requestManager);

    auto requestFactory = RequestFactoryImpl::Create();
    ENSURE_OR_RETURN_VAL(requestFactory != nullptr, nullptr);
    singletonManager.SetRequestFactory(requestFactory);

    auto miscManager = MiscManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(miscManager != nullptr, nullptr);
    singletonManager.SetMiscManager(miscManager);

#ifndef ENABLE_TEST
    auto securityAgent = SecurityAgentImpl::Create();
    ENSURE_OR_RETURN_VAL(securityAgent != nullptr, nullptr);
    singletonManager.SetSecurityAgent(securityAgent);
#endif // ENABLE_TEST

    auto registry = IncomingMessageHandlerRegistry::Create();
    ENSURE_OR_RETURN_VAL(registry != nullptr, nullptr);
    singletonManager.SetIncomingMessageHandlerRegistry(registry);

    return registry;
}

std::shared_ptr<CompanionDeviceAuthServiceInner> CompanionDeviceAuthServiceInner::CreateStep3(
    const std::shared_ptr<IncomingMessageHandlerRegistry> &registry)
{
    auto &singletonManager = SingletonManager::GetInstance();

    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;

#ifdef HAS_SOFT_BUS_CHANNEL
    auto softBusChannel = SoftBusChannel::Create();
    if (softBusChannel != nullptr) {
        channels.push_back(softBusChannel);
    }
#endif

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

#ifdef HAS_USER_AUTH_FRAMEWORK
    if (FwkCommManager::Create() == nullptr) {
        IAM_LOGE("failed to create FwkCommManager");
        return nullptr;
    }
#endif

    auto inner = std::shared_ptr<CompanionDeviceAuthServiceInner>(
        new (std::nothrow) CompanionDeviceAuthServiceInner(subscriptionManager));
    ENSURE_OR_RETURN_VAL(inner != nullptr, nullptr);
    IAM_LOGI("End");
    return inner;
}

ResultCode CompanionDeviceAuthServiceInner::SubscribeAvailableDeviceStatus(int32_t localUserId,
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback)
{
    IAM_LOGI("Start");
    if (deviceStatusCallback == nullptr) {
        IAM_LOGE("deviceStatusCallback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }

    if (localUserId != GetUserIdManager().GetActiveUserId()) {
        IAM_LOGE("userId %{public}d is not the active user id %{public}d", localUserId,
            GetUserIdManager().GetActiveUserId());
        return ResultCode::GENERAL_ERROR;
    }

    subscriptionManager_.AddAvailableDeviceStatusCallback(localUserId, deviceStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode CompanionDeviceAuthServiceInner::UnsubscribeAvailableDeviceStatus(
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback)
{
    IAM_LOGI("Start");
    if (deviceStatusCallback == nullptr) {
        IAM_LOGE("deviceStatusCallback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }

    subscriptionManager_.RemoveAvailableDeviceStatusCallback(deviceStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode CompanionDeviceAuthServiceInner::SubscribeTemplateStatusChange(int32_t localUserId,
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback)
{
    IAM_LOGI("Start");
    if (templateStatusCallback == nullptr) {
        IAM_LOGE("templateStatusCallback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }

    if (localUserId != GetUserIdManager().GetActiveUserId()) {
        IAM_LOGE("userId %{public}d is not the active user id %{public}d", localUserId,
            GetUserIdManager().GetActiveUserId());
        return ResultCode::GENERAL_ERROR;
    }

    subscriptionManager_.AddTemplateStatusCallback(localUserId, templateStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode CompanionDeviceAuthServiceInner::UnsubscribeTemplateStatusChange(
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback)
{
    IAM_LOGI("Start");
    if (templateStatusCallback == nullptr) {
        IAM_LOGE("templateStatusCallback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }

    subscriptionManager_.RemoveTemplateStatusCallback(templateStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode CompanionDeviceAuthServiceInner::SubscribeContinuousAuthStatusChange(
    const IpcSubscribeContinuousAuthStatusParam &subscribeContinuousAuthStatusParam,
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback)
{
    IAM_LOGI("Start");
    if (continuousAuthStatusCallback == nullptr) {
        IAM_LOGE("continuousAuthStatusCallback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }

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
    subscriptionManager_.AddContinuousAuthStatusCallback(subscribeContinuousAuthStatusParam.localUserId,
        subscriptionTemplateId, continuousAuthStatusCallback);

    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode CompanionDeviceAuthServiceInner::UnsubscribeContinuousAuthStatusChange(
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback)
{
    IAM_LOGI("Start");
    if (continuousAuthStatusCallback == nullptr) {
        IAM_LOGE("continuousAuthStatusCallback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }

    subscriptionManager_.RemoveContinuousAuthStatusCallback(continuousAuthStatusCallback);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode CompanionDeviceAuthServiceInner::UpdateTemplateEnabledBusinessIds(uint64_t templateId,
    const std::vector<int32_t> &enabledBusinessIds)
{
    IAM_LOGI("Start");

    // Convert int32_t to BusinessId for internal APIs
    std::vector<BusinessId> businessIdEnums;
    businessIdEnums.reserve(enabledBusinessIds.size());
    for (const auto &id : enabledBusinessIds) {
        businessIdEnums.push_back(static_cast<BusinessId>(id));
    }

    for (const auto &businessId : businessIdEnums) {
        if (businessId != BusinessId::DEFAULT) {
            IAM_LOGE("Invalid businessId:%{public}d", businessId);
            return ResultCode::INVALID_BUSINESS_ID;
        }
    }

    ResultCode ret =
        GetCompanionManager().UpdateCompanionEnabledBusinessIds(static_cast<TemplateId>(templateId), businessIdEnums);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("UpdateCompanionEnabledBusinessIds failed ret=%{public}d", ret);
        return ret;
    }

    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode CompanionDeviceAuthServiceInner::GetTemplateStatus(int32_t localUserId,
    std::vector<IpcTemplateStatus> &templateStatusArray)
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
        ipcStatus.isConfirmed =
            manageSubscribeTime.has_value() && (status.lastCheckTime >= manageSubscribeTime.value());
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

ResultCode CompanionDeviceAuthServiceInner::RegisterDeviceSelectCallback(uint32_t tokenId,
    const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback)
{
    IAM_LOGI("Start");
    if (deviceSelectCallback == nullptr) {
        IAM_LOGE("deviceSelectCallback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }

    if (!GetMiscManager().SetDeviceSelectCallback(tokenId, deviceSelectCallback)) {
        IAM_LOGE("failed to SetDeviceSelectCallback");
        return ResultCode::GENERAL_ERROR;
    }

    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

ResultCode CompanionDeviceAuthServiceInner::UnregisterDeviceSelectCallback(uint32_t tokenId)
{
    IAM_LOGI("Start");
    GetMiscManager().ClearDeviceSelectCallback(tokenId);
    IAM_LOGI("End");
    return ResultCode::SUCCESS;
}

bool CompanionDeviceAuthServiceInner::CheckLocalUserIdValid(int32_t localUserId)
{
    IAM_LOGI("Start");
    bool isUserIdValid = GetUserIdManager().IsUserIdValid(localUserId);
    IAM_LOGI("End, isUserIdValid=%{public}d", isUserIdValid);
    return isUserIdValid;
}

sptr<CompanionDeviceAuthService> CompanionDeviceAuthService::GetInstance()
{
    static sptr<CompanionDeviceAuthService> instance = sptr<CompanionDeviceAuthService>::MakeSptr();
    return instance;
}

CompanionDeviceAuthService::CompanionDeviceAuthService() : SystemAbility(COMPANION_DEVICE_AUTH_SA_ID, true)
{
}

bool CompanionDeviceAuthService::CheckPermission(int32_t &companionDeviceAuthResult)
{
    if (!GetAccessTokenKitAdapter().CheckPermission(*this, USE_USER_IDM_PERMISSION)) {
        IAM_LOGE("check use user idm permission failed");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::CHECK_PERMISSION_FAILED);
        return false;
    }
    if (!GetAccessTokenKitAdapter().CheckSystemPermission(*this)) {
        IAM_LOGE("check is system app permission failed");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::CHECK_SYSTEM_PERMISSION_FAILED);
        return false;
    }
    return true;
}

void CompanionDeviceAuthService::OnStart()
{
    IAM_LOGI("Start");
    auto innerOpt =
        RunOnResidentSync([]() { return CompanionDeviceAuthServiceInner::Create(); }, MAX_ON_START_WAIT_TIME_SEC);
    if (!innerOpt.has_value() || innerOpt.value() == nullptr) {
        IAM_LOGE("failed to create inner service");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner_ = innerOpt.value();
    }

    if (!Publish(CompanionDeviceAuthService::GetInstance())) {
        IAM_LOGE("fail to publish companion device auth service");
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner_.reset();
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
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<CompanionDeviceAuthServiceInner> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, localUserId, deviceStatusCallback]() {
        return inner->SubscribeAvailableDeviceStatus(localUserId, deviceStatusCallback);
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
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<CompanionDeviceAuthServiceInner> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync(
        [inner, deviceStatusCallback]() { return inner->UnsubscribeAvailableDeviceStatus(deviceStatusCallback); });
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
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<CompanionDeviceAuthServiceInner> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, localUserId, templateStatusCallback]() {
        return inner->SubscribeTemplateStatusChange(localUserId, templateStatusCallback);
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
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<CompanionDeviceAuthServiceInner> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync(
        [inner, templateStatusCallback]() { return inner->UnsubscribeTemplateStatusChange(templateStatusCallback); });
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
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<CompanionDeviceAuthServiceInner> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, subscribeContinuousAuthStatusParam, continuousAuthStatusCallback]() {
        return inner->SubscribeContinuousAuthStatusChange(subscribeContinuousAuthStatusParam,
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
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<CompanionDeviceAuthServiceInner> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, continuousAuthStatusCallback]() {
        return inner->UnsubscribeContinuousAuthStatusChange(continuousAuthStatusCallback);
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
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<CompanionDeviceAuthServiceInner> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, templateId, enabledBusinessIds]() {
        return inner->UpdateTemplateEnabledBusinessIds(templateId, enabledBusinessIds);
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
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<CompanionDeviceAuthServiceInner> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultPair = RunOnResidentSync([inner, localUserId]() {
        std::vector<IpcTemplateStatus> array;
        ResultCode result = inner->GetTemplateStatus(localUserId, array);
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
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<CompanionDeviceAuthServiceInner> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    uint32_t tokenId = GetAccessTokenKitAdapter().GetAccessTokenId(*this);
    ENSURE_OR_RETURN_VAL(tokenId != 0, ResultCode::GENERAL_ERROR);
    auto resultOpt = RunOnResidentSync([inner, deviceSelectCallback, tokenId]() {
        return inner->RegisterDeviceSelectCallback(tokenId, deviceSelectCallback);
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
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<CompanionDeviceAuthServiceInner> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    uint32_t tokenId = GetAccessTokenKitAdapter().GetAccessTokenId(*this);
    ENSURE_OR_RETURN_VAL(tokenId != 0, ResultCode::GENERAL_ERROR);
    auto resultOpt = RunOnResidentSync([inner, tokenId]() { return inner->UnregisterDeviceSelectCallback(tokenId); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnregisterDeviceSelectCallback timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::CheckLocalUserIdValid(int32_t localUserId, bool &isUserIdValid,
    int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<CompanionDeviceAuthServiceInner> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, localUserId]() { return inner->CheckLocalUserIdValid(localUserId); });
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

    TaskRunnerManager::GetInstance().PostTaskOnResident([task = std::forward<Func>(func), promise]() mutable {
        try {
            promise->set_value(task());
        } catch (...) {
            IAM_LOGE("RunOnResidentSync task exception");
        }
    });

    if (future.wait_for(std::chrono::seconds(timeoutSec)) != std::future_status::ready) {
        IAM_LOGE("RunOnResidentSync timeout - task not completed in %{public}u second", timeoutSec);
        return std::nullopt;
    }

    return future.get();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
