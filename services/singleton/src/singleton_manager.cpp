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

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_SINGLETON_MANAGER

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
    IExecutorFactory &GetExecutorFactory() override;
    void SetExecutorFactory(std::shared_ptr<IExecutorFactory> executorFactory) override;

    IEventBus &GetEventBus() override;
    void SetEventBus(std::shared_ptr<IEventBus> eventBus) override;

#ifdef ENABLE_TEST
    virtual void Reset() override;
#endif // ENABLE_TEST

private:
    void AbortIfSingletonUninitialized();

    std::shared_ptr<ICompanionManager> companionManager_;
    std::shared_ptr<IHostBindingManager> hostBindingManager_;
    std::shared_ptr<IMiscManager> miscManager_;
    std::shared_ptr<ISecurityAgent> securityAgent_;
    std::shared_ptr<ICrossDeviceCommManager> crossDeviceCommManager_;
    std::shared_ptr<IRequestManager> requestManager_;
    std::shared_ptr<IRequestFactory> requestFactory_;
    std::shared_ptr<IncomingMessageHandlerRegistry> incomingMessageHandlerRegistry_;
    std::shared_ptr<IExecutorFactory> executorFactory_;
    std::shared_ptr<IEventBus> eventBus_;
};

#ifdef ENABLE_TEST
void SingletonManagerImpl::Reset()
{
    companionManager_.reset();
    hostBindingManager_.reset();
    miscManager_.reset();
    securityAgent_.reset();
    crossDeviceCommManager_.reset();
    requestManager_.reset();
    requestFactory_.reset();
    incomingMessageHandlerRegistry_.reset();
    executorFactory_.reset();
    eventBus_.reset();
}
#endif // ENABLE_TEST

ICompanionManager &SingletonManagerImpl::GetCompanionManager()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    if (companionManager_ == nullptr) {
        IAM_LOGE("companion manager is not initialized");
        AbortIfSingletonUninitialized();
    }
    return *companionManager_;
}

void SingletonManagerImpl::SetCompanionManager(std::shared_ptr<ICompanionManager> companionManager)
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    ENSURE_OR_RETURN(companionManager != nullptr);
    if (companionManager_ != nullptr) {
        IAM_LOGE("companion manager is already set");
        return;
    }
    companionManager_ = companionManager;
}

IHostBindingManager &SingletonManagerImpl::GetHostBindingManager()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    if (hostBindingManager_ == nullptr) {
        IAM_LOGE("host binding manager is not initialized");
        AbortIfSingletonUninitialized();
    }
    return *hostBindingManager_;
}

void SingletonManagerImpl::SetHostBindingManager(std::shared_ptr<IHostBindingManager> hostBindingManager)
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    ENSURE_OR_RETURN(hostBindingManager != nullptr);
    if (hostBindingManager_ != nullptr) {
        IAM_LOGE("host binding manager is already set");
        return;
    }
    hostBindingManager_ = hostBindingManager;
}

IMiscManager &SingletonManagerImpl::GetMiscManager()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    if (miscManager_ == nullptr) {
        IAM_LOGE("misc manager is not initialized");
        AbortIfSingletonUninitialized();
    }
    return *miscManager_;
}

void SingletonManagerImpl::SetMiscManager(std::shared_ptr<IMiscManager> miscManager)
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    ENSURE_OR_RETURN(miscManager != nullptr);
    if (miscManager_ != nullptr) {
        IAM_LOGE("misc manager is already set");
        return;
    }
    miscManager_ = miscManager;
}

ISecurityAgent &SingletonManagerImpl::GetSecurityAgent()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    if (securityAgent_ == nullptr) {
        IAM_LOGE("security agent is not initialized");
        AbortIfSingletonUninitialized();
    }
    return *securityAgent_;
}

void SingletonManagerImpl::SetSecurityAgent(std::shared_ptr<ISecurityAgent> securityAgent)
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    ENSURE_OR_RETURN(securityAgent != nullptr);
    if (securityAgent_ != nullptr) {
        IAM_LOGE("security agent is already set");
        return;
    }
    securityAgent_ = securityAgent;
}

void SingletonManagerImpl::SetCrossDeviceCommManager(std::shared_ptr<ICrossDeviceCommManager> crossDeviceCommManager)
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    ENSURE_OR_RETURN(crossDeviceCommManager != nullptr);
    if (crossDeviceCommManager_ != nullptr) {
        IAM_LOGE("cross device comm manager is already set");
        return;
    }
    crossDeviceCommManager_ = crossDeviceCommManager;
}

ICrossDeviceCommManager &SingletonManagerImpl::GetCrossDeviceCommManager()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    if (crossDeviceCommManager_ == nullptr) {
        IAM_LOGE("cross device comm manager is not initialized");
        AbortIfSingletonUninitialized();
    }
    return *crossDeviceCommManager_;
}

IRequestManager &SingletonManagerImpl::GetRequestManager()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    if (requestManager_ == nullptr) {
        IAM_LOGE("request manager is not initialized");
        AbortIfSingletonUninitialized();
    }
    return *requestManager_;
}

void SingletonManagerImpl::SetRequestManager(std::shared_ptr<IRequestManager> requestManager)
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    ENSURE_OR_RETURN(requestManager != nullptr);
    if (requestManager_ != nullptr) {
        IAM_LOGE("request manager is already set");
        return;
    }
    requestManager_ = requestManager;
}

IRequestFactory &SingletonManagerImpl::GetRequestFactory()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    if (requestFactory_ == nullptr) {
        IAM_LOGE("request factory is not initialized");
        AbortIfSingletonUninitialized();
    }
    return *requestFactory_;
}

void SingletonManagerImpl::SetRequestFactory(std::shared_ptr<IRequestFactory> requestFactory)
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    ENSURE_OR_RETURN(requestFactory != nullptr);
    if (requestFactory_ != nullptr) {
        IAM_LOGE("request factory is already set");
        return;
    }
    requestFactory_ = requestFactory;
}

IncomingMessageHandlerRegistry &SingletonManagerImpl::GetIncomingMessageHandlerRegistry()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    if (incomingMessageHandlerRegistry_ == nullptr) {
        IAM_LOGE("incoming message handler registry is not initialized");
        AbortIfSingletonUninitialized();
    }
    return *incomingMessageHandlerRegistry_;
}

void SingletonManagerImpl::SetIncomingMessageHandlerRegistry(std::shared_ptr<IncomingMessageHandlerRegistry> registry)
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    ENSURE_OR_RETURN(registry != nullptr);
    if (incomingMessageHandlerRegistry_ != nullptr) {
        IAM_LOGE("incoming message handler registry is already set");
        return;
    }
    incomingMessageHandlerRegistry_ = registry;
}

IExecutorFactory &SingletonManagerImpl::GetExecutorFactory()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    if (executorFactory_ == nullptr) {
        IAM_LOGE("executor factory is not initialized");
        AbortIfSingletonUninitialized();
    }
    return *executorFactory_;
}

void SingletonManagerImpl::SetExecutorFactory(std::shared_ptr<IExecutorFactory> executorFactory)
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    ENSURE_OR_RETURN(executorFactory != nullptr);
    if (executorFactory_ != nullptr) {
        IAM_LOGE("executor factory is already set");
        return;
    }
    executorFactory_ = executorFactory;
}

IEventBus &SingletonManagerImpl::GetEventBus()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    if (eventBus_ == nullptr) {
        IAM_LOGE("event bus is not initialized");
        AbortIfSingletonUninitialized();
    }
    return *eventBus_;
}

void SingletonManagerImpl::SetEventBus(std::shared_ptr<IEventBus> eventBus)
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    ENSURE_OR_RETURN(eventBus != nullptr);
    if (eventBus_ != nullptr) {
        IAM_LOGE("event bus is already set");
        return;
    }
    eventBus_ = eventBus;
}

void SingletonManagerImpl::AbortIfSingletonUninitialized()
{
    IAM_LOGE("singleton is not initialized, abort");
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
