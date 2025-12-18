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

#include "singleton_manager.h"

#include <cstdlib>

#include "iam_check.h"
#include "iam_logger.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class SingletonManagerImpl final : public SingletonManager {
public:
    ~SingletonManagerImpl() override = default;

    ICompanionManager &GetCompanionManager() override;
    void SetCompanionManager(std::shared_ptr<ICompanionManager> companionManager) override;
    IHostBindingManager &GetHostBindingManager() override;
    void SetHostBindingManager(std::shared_ptr<IHostBindingManager> hostBindingManager) override;
    IMiscManager &GetMiscManager() override;
    void SetMiscManager(std::shared_ptr<IMiscManager> miscManager) override;
    ISystemParamManager &GetSystemParamManager() override;
    void SetSystemParamManager(std::shared_ptr<ISystemParamManager> systemParamManager) override;
    IActiveUserIdManager &GetActiveUserIdManager() override;
    void SetActiveUserIdManager(std::shared_ptr<IActiveUserIdManager> activeUserIdManager) override;
    ISecurityAgent &GetSecurityAgent() override;
    void SetSecurityAgent(std::shared_ptr<ISecurityAgent> securityAgent) override;
    ICrossDeviceCommManager &GetCrossDeviceCommManager() override;
    void SetCrossDeviceCommManager(std::shared_ptr<ICrossDeviceCommManager> crossDeviceCommManager) override;
    IRequestManager &GetRequestManager() override;
    void SetRequestManager(std::shared_ptr<IRequestManager> requestManager) override;
    IRequestFactory &GetRequestFactory() override;
    void SetRequestFactory(std::shared_ptr<IRequestFactory> requestFactory) override;
    IncomingMessageHandlerRegistry &GetIncomingMessageHandlerRegistry() override;
    void SetIncomingMessageHandlerRegistry(std::shared_ptr<IncomingMessageHandlerRegistry> registry) override;

#ifdef ENABLE_TEST
    virtual void Reset() override;
#endif

private:
    void AbortIfSingletonUninitialized();

    std::shared_ptr<ICompanionManager> companionManager_;
    std::shared_ptr<IHostBindingManager> hostBindingManager_;
    std::shared_ptr<IMiscManager> miscManager_;
    std::shared_ptr<ISystemParamManager> systemParamManager_;
    std::shared_ptr<IActiveUserIdManager> activeUserIdManager_;
    std::shared_ptr<ISecurityAgent> securityAgent_;
    std::shared_ptr<ICrossDeviceCommManager> crossDeviceCommManager_;
    std::shared_ptr<IRequestManager> requestManager_;
    std::shared_ptr<IRequestFactory> requestFactory_;
    std::shared_ptr<IncomingMessageHandlerRegistry> incomingMessageHandlerRegistry_;
};

#ifdef ENABLE_TEST
void SingletonManagerImpl::Reset()
{
    companionManager_.reset();
    hostBindingManager_.reset();
    miscManager_.reset();
    systemParamManager_.reset();
    activeUserIdManager_.reset();
    securityAgent_.reset();
    crossDeviceCommManager_.reset();
    requestManager_.reset();
    requestFactory_.reset();
    incomingMessageHandlerRegistry_.reset();
}
#endif

ICompanionManager &SingletonManagerImpl::GetCompanionManager()
{
    TaskRunnerManager::GetInstance().AssertRunningOnResidentThread();
    if (companionManager_ == nullptr) {
        AbortIfSingletonUninitialized();
    }
    return *companionManager_;
}

void SingletonManagerImpl::SetCompanionManager(std::shared_ptr<ICompanionManager> companionManager)
{
    ENSURE_OR_RETURN(companionManager != nullptr);
    if (companionManager_ != nullptr) {
        IAM_LOGE("companion manager is already set");
        return;
    }
    companionManager_ = companionManager;
}

IHostBindingManager &SingletonManagerImpl::GetHostBindingManager()
{
    TaskRunnerManager::GetInstance().AssertRunningOnResidentThread();
    if (hostBindingManager_ == nullptr) {
        AbortIfSingletonUninitialized();
    }
    return *hostBindingManager_;
}

void SingletonManagerImpl::SetHostBindingManager(std::shared_ptr<IHostBindingManager> hostBindingManager)
{
    ENSURE_OR_RETURN(hostBindingManager != nullptr);
    if (hostBindingManager_ != nullptr) {
        IAM_LOGE("host binding manager is already set");
        return;
    }
    hostBindingManager_ = hostBindingManager;
}

IMiscManager &SingletonManagerImpl::GetMiscManager()
{
    TaskRunnerManager::GetInstance().AssertRunningOnResidentThread();
    if (miscManager_ == nullptr) {
        AbortIfSingletonUninitialized();
    }
    return *miscManager_;
}

void SingletonManagerImpl::SetMiscManager(std::shared_ptr<IMiscManager> miscManager)
{
    ENSURE_OR_RETURN(miscManager != nullptr);
    if (miscManager_ != nullptr) {
        IAM_LOGE("misc manager is already set");
        return;
    }
    miscManager_ = miscManager;
}

ISystemParamManager &SingletonManagerImpl::GetSystemParamManager()
{
    TaskRunnerManager::GetInstance().AssertRunningOnResidentThread();
    if (systemParamManager_ == nullptr) {
        AbortIfSingletonUninitialized();
    }
    return *systemParamManager_;
}

void SingletonManagerImpl::SetSystemParamManager(std::shared_ptr<ISystemParamManager> systemParamManager)
{
    ENSURE_OR_RETURN(systemParamManager != nullptr);
    if (systemParamManager_ != nullptr) {
        IAM_LOGE("system param manager is already set");
        return;
    }
    systemParamManager_ = systemParamManager;
}

IActiveUserIdManager &SingletonManagerImpl::GetActiveUserIdManager()
{
    TaskRunnerManager::GetInstance().AssertRunningOnResidentThread();
    if (activeUserIdManager_ == nullptr) {
        AbortIfSingletonUninitialized();
    }
    return *activeUserIdManager_;
}

void SingletonManagerImpl::SetActiveUserIdManager(std::shared_ptr<IActiveUserIdManager> activeUserIdManager)
{
    ENSURE_OR_RETURN(activeUserIdManager != nullptr);
    if (activeUserIdManager_ != nullptr) {
        IAM_LOGE("active user id manager is already set");
        return;
    }
    activeUserIdManager_ = activeUserIdManager;
}

ISecurityAgent &SingletonManagerImpl::GetSecurityAgent()
{
    TaskRunnerManager::GetInstance().AssertRunningOnResidentThread();
    if (securityAgent_ == nullptr) {
        AbortIfSingletonUninitialized();
    }
    return *securityAgent_;
}

void SingletonManagerImpl::SetSecurityAgent(std::shared_ptr<ISecurityAgent> securityAgent)
{
    ENSURE_OR_RETURN(securityAgent != nullptr);
    if (securityAgent_ != nullptr) {
        IAM_LOGE("security agent is already set");
        return;
    }
    securityAgent_ = securityAgent;
}

void SingletonManagerImpl::SetCrossDeviceCommManager(std::shared_ptr<ICrossDeviceCommManager> crossDeviceCommManager)
{
    ENSURE_OR_RETURN(crossDeviceCommManager != nullptr);
    if (crossDeviceCommManager_ != nullptr) {
        IAM_LOGE("cross device comm manager is already set");
        return;
    }
    crossDeviceCommManager_ = crossDeviceCommManager;
}

ICrossDeviceCommManager &SingletonManagerImpl::GetCrossDeviceCommManager()
{
    TaskRunnerManager::GetInstance().AssertRunningOnResidentThread();
    if (crossDeviceCommManager_ == nullptr) {
        AbortIfSingletonUninitialized();
    }
    return *crossDeviceCommManager_;
}

IRequestManager &SingletonManagerImpl::GetRequestManager()
{
    TaskRunnerManager::GetInstance().AssertRunningOnResidentThread();
    if (requestManager_ == nullptr) {
        AbortIfSingletonUninitialized();
    }
    return *requestManager_;
}

void SingletonManagerImpl::SetRequestManager(std::shared_ptr<IRequestManager> requestManager)
{
    ENSURE_OR_RETURN(requestManager != nullptr);
    if (requestManager_ != nullptr) {
        IAM_LOGE("request manager is already set");
        return;
    }
    requestManager_ = requestManager;
}

IRequestFactory &SingletonManagerImpl::GetRequestFactory()
{
    TaskRunnerManager::GetInstance().AssertRunningOnResidentThread();
    if (requestFactory_ == nullptr) {
        AbortIfSingletonUninitialized();
    }
    return *requestFactory_;
}

void SingletonManagerImpl::SetRequestFactory(std::shared_ptr<IRequestFactory> requestFactory)
{
    ENSURE_OR_RETURN(requestFactory != nullptr);
    if (requestFactory_ != nullptr) {
        IAM_LOGE("request factory is already set");
        return;
    }
    requestFactory_ = requestFactory;
}

IncomingMessageHandlerRegistry &SingletonManagerImpl::GetIncomingMessageHandlerRegistry()
{
    TaskRunnerManager::GetInstance().AssertRunningOnResidentThread();
    if (incomingMessageHandlerRegistry_ == nullptr) {
        AbortIfSingletonUninitialized();
    }
    return *incomingMessageHandlerRegistry_;
}

void SingletonManagerImpl::SetIncomingMessageHandlerRegistry(std::shared_ptr<IncomingMessageHandlerRegistry> registry)
{
    ENSURE_OR_RETURN(registry != nullptr);
    if (incomingMessageHandlerRegistry_ != nullptr) {
        IAM_LOGE("incoming message handler registry is already set");
        return;
    }
    incomingMessageHandlerRegistry_ = registry;
}

void SingletonManagerImpl::AbortIfSingletonUninitialized()
{
    IAM_LOGF("singleton is not initialized, abort");
    std::abort();
}
} // namespace

SingletonManager &SingletonManager::GetInstance()
{
    static SingletonManagerImpl instance;
    return instance;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
