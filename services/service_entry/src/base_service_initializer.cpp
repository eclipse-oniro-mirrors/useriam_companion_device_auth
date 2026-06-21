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

#include "base_service_initializer.h"

#include <memory>
#include <new>

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "companion_manager_impl.h"
#include "cross_device_comm_manager_impl.h"
#include "default_executor_factory.h"
#include "driver_manager_adapter_impl.h"
#include "event_bus_impl.h"
#include "event_manager_adapter_impl.h"
#include "fwk_comm_manager.h"
#include "host_binding_manager_impl.h"
#include "icross_device_channel.h"
#include "idm_adapter_impl.h"
#include "incoming_message_handler_registry.h"
#include "misc_manager_impl.h"
#include "request_factory_impl.h"
#include "request_manager_impl.h"
#include "sa_manager_adapter_impl.h"
#include "security_agent_impl.h"
#include "security_command_adapter_impl.h"
#include "singleton_manager.h"
#include "soft_bus_channel.h"
#include "subscription_manager.h"
#include "system_param_manager_impl.h"
#include "time_keeper_impl.h"
#include "user_auth_adapter_impl.h"
#include "user_id_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_BASE_SERVICE_INITIALIZER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<BaseServiceInitializer> BaseServiceInitializer::Create()
{
    IAM_LOGI("Start");

    DeviceCapabilityInfo deviceCapabilityInfo;
    deviceCapabilityInfo.hostSupportedBusinessIds = { BusinessId::DEFAULT };
    deviceCapabilityInfo.hostLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH,
        Capability::OBTAIN_TOKEN };
    deviceCapabilityInfo.companionSupportedBusinessIds = { BusinessId::DEFAULT };
    deviceCapabilityInfo.companionLocalCapabilities = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH,
        Capability::OBTAIN_TOKEN };

    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    ENSURE_OR_RETURN_VAL(subscriptionManager != nullptr, nullptr);
    auto initializer = std::shared_ptr<BaseServiceInitializer>(new (std::nothrow) BaseServiceInitializer(
        subscriptionManager, deviceCapabilityInfo, true));
    ENSURE_OR_RETURN_VAL(initializer != nullptr, nullptr);

    if (!initializer->Initialize()) {
        IAM_LOGE("failed to initialize service");
        return nullptr;
    }

    IAM_LOGI("End");
    return initializer;
}

bool BaseServiceInitializer::Initialize()
{
    // Execute basic initialization steps in table order (compile-time defined, zero overhead)
    for (size_t i = 0; i < BASIC_INIT_TABLE_SIZE; ++i) {
        ENSURE_OR_RETURN_VAL(BASIC_INIT_TABLE[i].func != nullptr, false);
        IAM_LOGI("Executing initialization step %{public}zu/%{public}zu: %{public}s", i + 1, BASIC_INIT_TABLE_SIZE,
            BASIC_INIT_TABLE[i].name != nullptr ? BASIC_INIT_TABLE[i].name : "unknown");
        bool result = (this->*BASIC_INIT_TABLE[i].func)();
        if (!result) {
            IAM_LOGE("Initialization step %{public}s failed",
                BASIC_INIT_TABLE[i].name != nullptr ? BASIC_INIT_TABLE[i].name : "unknown");
            return false;
        }
    }

    // Execute dependent initialization steps (have complex dependencies)
    if (!InitializeDependentSteps()) {
        IAM_LOGE("InitializeDependentSteps failed");
        return false;
    }

    return true;
}

bool BaseServiceInitializer::InitializeDependentSteps()
{
    if (!InitializeChannels()) {
        IAM_LOGE("InitializeChannels failed");
        return false;
    }

    if (!InitializeCrossDeviceCommManager()) {
        IAM_LOGE("InitializeCrossDeviceCommManager failed");
        return false;
    }

    if (!InitializeCompanionManager()) {
        IAM_LOGE("InitializeCompanionManager failed");
        return false;
    }

    if (!InitializeHostBindingManager()) {
        IAM_LOGE("InitializeHostBindingManager failed");
        return false;
    }

    if (!RegisterHandlers()) {
        IAM_LOGE("RegisterHandlers failed");
        return false;
    }

    if (!StartCrossDeviceCommManager()) {
        IAM_LOGE("StartCrossDeviceCommManager failed");
        return false;
    }

    if (!InitializeFwkComm()) {
        IAM_LOGE("InitializeFwkComm failed");
        return false;
    }

    if (!InitializeExtension()) {
        IAM_LOGE("InitializeExtension failed");
        return false;
    }

    return true;
}

bool BaseServiceInitializer::InitializeTimeKeeper()
{
    auto &adapterManager = AdapterManager::GetInstance();
    auto timeKeeper = TimeKeeperImpl::Create();
    ENSURE_OR_RETURN_VAL(timeKeeper != nullptr, false);
    adapterManager.SetTimeKeeper(timeKeeper);
    return true;
}

bool BaseServiceInitializer::InitializeEventManagerAdapter()
{
    auto &adapterManager = AdapterManager::GetInstance();
    auto eventManagerAdapter = std::make_shared<EventManagerAdapterImpl>();
    ENSURE_OR_RETURN_VAL(eventManagerAdapter != nullptr, false);
    adapterManager.SetEventManagerAdapter(eventManagerAdapter);
    return true;
}

bool BaseServiceInitializer::InitializeSaManagerAdapter()
{
    auto &adapterManager = AdapterManager::GetInstance();
    auto saManagerAdapter = std::make_shared<SaManagerAdapterImpl>();
    ENSURE_OR_RETURN_VAL(saManagerAdapter != nullptr, false);
    adapterManager.SetSaManagerAdapter(saManagerAdapter);
    return true;
}

bool BaseServiceInitializer::InitializeSecurityCommandAdapter()
{
#ifndef STATIC_LIBRARY
    auto &adapterManager = AdapterManager::GetInstance();
    auto securityCommandAdapter = SecurityCommandAdapterImpl::Create();
    ENSURE_OR_RETURN_VAL(securityCommandAdapter != nullptr, false);
    adapterManager.SetSecurityCommandAdapter(securityCommandAdapter);
    return true;
#else
    IAM_LOGE("STATIC_LIBRARY is defined, InitializeSecurityCommandAdapter must be override");
    return false;
#endif
}

bool BaseServiceInitializer::InitializeSystemParamManager()
{
    auto &adapterManager = AdapterManager::GetInstance();
    auto systemParamManager = SystemParamManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(systemParamManager != nullptr, false);
    adapterManager.SetSystemParamManager(systemParamManager);
    return true;
}

bool BaseServiceInitializer::InitializeUserIdManager()
{
    auto &adapterManager = AdapterManager::GetInstance();
    auto userIdManager = IUserIdManager::Create();
    ENSURE_OR_RETURN_VAL(userIdManager != nullptr, false);
    adapterManager.SetUserIdManager(userIdManager);
    return true;
}

bool BaseServiceInitializer::InitializeUserAuthFramework()
{
    auto &adapterManager = AdapterManager::GetInstance();
    auto userAuthAdapter = std::make_shared<UserAuthAdapterImpl>();
    ENSURE_OR_RETURN_VAL(userAuthAdapter != nullptr, false);
    adapterManager.SetUserAuthAdapter(userAuthAdapter);

    auto driverManagerAdapter = std::make_shared<DriverManagerAdapterImpl>();
    ENSURE_OR_RETURN_VAL(driverManagerAdapter != nullptr, false);
    adapterManager.SetDriverManagerAdapter(driverManagerAdapter);

    auto idmAdapter = IdmAdapterImpl::Create();
    ENSURE_OR_RETURN_VAL(idmAdapter != nullptr, false);
    adapterManager.SetIdmAdapter(idmAdapter);
    return true;
}

bool BaseServiceInitializer::InitializeRequestManager()
{
    auto requestManager = RequestManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(requestManager != nullptr, false);
    SingletonManager::GetInstance().SetRequestManager(requestManager);
    return true;
}

bool BaseServiceInitializer::InitializeRequestFactory()
{
    auto requestFactory = RequestFactoryImpl::Create();
    ENSURE_OR_RETURN_VAL(requestFactory != nullptr, false);
    SingletonManager::GetInstance().SetRequestFactory(requestFactory);
    return true;
}

bool BaseServiceInitializer::InitializeMiscManager()
{
    auto miscManager = MiscManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(miscManager != nullptr, false);
    SingletonManager::GetInstance().SetMiscManager(miscManager);
    return true;
}

bool BaseServiceInitializer::InitializeSecurityAgent()
{
#ifndef ENABLE_TEST
    auto securityAgent = SecurityAgentImpl::Create();
    ENSURE_OR_RETURN_VAL(securityAgent != nullptr, false);
    SingletonManager::GetInstance().SetSecurityAgent(securityAgent);
#endif
    return true;
}

bool BaseServiceInitializer::InitializeIncomingMessageHandlerRegistry()
{
    auto registry = IncomingMessageHandlerRegistry::Create();
    ENSURE_OR_RETURN_VAL(registry != nullptr, false);
    SingletonManager::GetInstance().SetIncomingMessageHandlerRegistry(registry);
    incomingMessageHandlerRegistryHolder_ = registry;
    return true;
}

bool BaseServiceInitializer::InitializeEventBus()
{
    auto eventBus = EventBusImpl::Create();
    ENSURE_OR_RETURN_VAL(eventBus != nullptr, false);
    SingletonManager::GetInstance().SetEventBus(eventBus);
    return true;
}

bool BaseServiceInitializer::InitializeChannels()
{
#ifdef HAS_SOFT_BUS_CHANNEL
    auto softBusChannel = SoftBusChannel::Create();
    if (softBusChannel != nullptr) {
        channelsHolder_.push_back(softBusChannel);
    }
#endif
    return true;
}

bool BaseServiceInitializer::InitializeCrossDeviceCommManager()
{
    DeviceCapabilityInfo deviceCapabilityInfo = {
        .hostSupportedBusinessIds = hostSupportedBusinessIds_,
        .hostLocalCapabilities = hostLocalCapabilities_,
        .companionSupportedBusinessIds = companionSupportedBusinessIds_,
        .companionLocalCapabilities = companionLocalCapabilities_
    };
    auto crossDeviceCommManager = CrossDeviceCommManagerImpl::Create(deviceCapabilityInfo, channelsHolder_,
        hostBindingRevokeTokenOnInactive_);
    ENSURE_OR_RETURN_VAL(crossDeviceCommManager != nullptr, false);
    SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommManager);
    return true;
}

bool BaseServiceInitializer::InitializeCompanionManager()
{
    auto companionManager = CompanionManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(companionManager != nullptr, false);
    SingletonManager::GetInstance().SetCompanionManager(companionManager);
    return true;
}

bool BaseServiceInitializer::InitializeHostBindingManager()
{
    auto hostBindingManager = HostBindingManagerImpl::Create();
    ENSURE_OR_RETURN_VAL(hostBindingManager != nullptr, false);
    SingletonManager::GetInstance().SetHostBindingManager(hostBindingManager);
    return true;
}

bool BaseServiceInitializer::RegisterHandlers()
{
    ENSURE_OR_RETURN_VAL(incomingMessageHandlerRegistryHolder_ != nullptr, false);
    return incomingMessageHandlerRegistryHolder_->RegisterHandlers();
}

bool BaseServiceInitializer::StartCrossDeviceCommManager()
{
    auto &crossDeviceCommManager = GetCrossDeviceCommManager();
    return crossDeviceCommManager.Start();
}

bool BaseServiceInitializer::InitializeFwkComm()
{
    auto executorFactory = ExecutorFactoryImpl::Create();
    ENSURE_OR_RETURN_VAL(executorFactory != nullptr, false);
    SingletonManager::GetInstance().SetExecutorFactory(executorFactory);

    if (FwkCommManager::Create() == nullptr) {
        IAM_LOGE("failed to create FwkCommManager");
        return false;
    }
    return true;
}

bool BaseServiceInitializer::InitializeExtension()
{
    return true;
}

// Compile-time defined initialization table (zero runtime overhead)
const BaseServiceInitializer::BasicInitStep BaseServiceInitializer::BASIC_INIT_TABLE[] = {
    { &BaseServiceInitializer::InitializeTimeKeeper, "InitializeTimeKeeper" },
    { &BaseServiceInitializer::InitializeMiscManager, "InitializeMiscManager" },
    { &BaseServiceInitializer::InitializeEventManagerAdapter, "InitializeEventManagerAdapter" },
    { &BaseServiceInitializer::InitializeSaManagerAdapter, "InitializeSaManagerAdapter" },
    { &BaseServiceInitializer::InitializeSecurityCommandAdapter, "InitializeSecurityCommandAdapter" },
    { &BaseServiceInitializer::InitializeSystemParamManager, "InitializeSystemParamManager" },
    { &BaseServiceInitializer::InitializeUserIdManager, "InitializeUserIdManager" },
    { &BaseServiceInitializer::InitializeUserAuthFramework, "InitializeUserAuthFramework" },
    { &BaseServiceInitializer::InitializeRequestManager, "InitializeRequestManager" },
    { &BaseServiceInitializer::InitializeRequestFactory, "InitializeRequestFactory" },
    { &BaseServiceInitializer::InitializeSecurityAgent, "InitializeSecurityAgent" },
    { &BaseServiceInitializer::InitializeIncomingMessageHandlerRegistry, "InitializeIncomingMessageHandlerRegistry" },
    { &BaseServiceInitializer::InitializeEventBus, "InitializeEventBus" },
};

const size_t BaseServiceInitializer::BASIC_INIT_TABLE_SIZE = sizeof(BASIC_INIT_TABLE) / sizeof(BASIC_INIT_TABLE[0]);

BaseServiceInitializer::BaseServiceInitializer(std::shared_ptr<SubscriptionManager> subscriptionManager,
    const DeviceCapabilityInfo &deviceCapabilityInfo, bool hostBindingRevokeTokenOnInactive)
    : subscriptionManagerHolder_(std::move(subscriptionManager)),
      hostSupportedBusinessIds_(deviceCapabilityInfo.hostSupportedBusinessIds),
      hostLocalCapabilities_(deviceCapabilityInfo.hostLocalCapabilities),
      companionSupportedBusinessIds_(deviceCapabilityInfo.companionSupportedBusinessIds),
      companionLocalCapabilities_(deviceCapabilityInfo.companionLocalCapabilities),
      hostBindingRevokeTokenOnInactive_(hostBindingRevokeTokenOnInactive)
{
}

std::shared_ptr<SubscriptionManager> BaseServiceInitializer::GetSubscriptionManager() const
{
    return subscriptionManagerHolder_;
}

const std::vector<BusinessId> &BaseServiceInitializer::GetHostSupportedBusinessIds() const
{
    return hostSupportedBusinessIds_;
}

const std::vector<Capability> &BaseServiceInitializer::GetHostLocalCapabilities() const
{
    return hostLocalCapabilities_;
}

const std::vector<BusinessId> &BaseServiceInitializer::GetCompanionSupportedBusinessIds() const
{
    return companionSupportedBusinessIds_;
}

const std::vector<Capability> &BaseServiceInitializer::GetCompanionLocalCapabilities() const
{
    return companionLocalCapabilities_;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
