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

#ifndef COMPANION_DEVICE_AUTH_SINGLETON_MANAGER_H
#define COMPANION_DEVICE_AUTH_SINGLETON_MANAGER_H

#include <memory>

#include "nocopyable.h"

#include "active_user_id_manager.h"
#include "companion_manager.h"
#include "cross_device_comm_manager.h"
#include "host_binding_manager.h"
#include "incoming_message_handler_registry.h"
#include "misc_manager.h"
#include "request_factory.h"
#include "request_manager.h"
#include "security_agent.h"
#include "system_param_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SingletonManager : public NoCopyable {
public:
    static SingletonManager &GetInstance();

    virtual ~SingletonManager() = default;

    virtual ICompanionManager &GetCompanionManager() = 0;
    virtual void SetCompanionManager(std::shared_ptr<ICompanionManager> companionDeviceManager) = 0;

    virtual IHostBindingManager &GetHostBindingManager() = 0;
    virtual void SetHostBindingManager(std::shared_ptr<IHostBindingManager> hostBindingManager) = 0;

    virtual IMiscManager &GetMiscManager() = 0;
    virtual void SetMiscManager(std::shared_ptr<IMiscManager> miscManager) = 0;

    virtual ISystemParamManager &GetSystemParamManager() = 0;
    virtual void SetSystemParamManager(std::shared_ptr<ISystemParamManager> systemParamManager) = 0;

    virtual IActiveUserIdManager &GetActiveUserIdManager() = 0;
    virtual void SetActiveUserIdManager(std::shared_ptr<IActiveUserIdManager> activeUserIdManager) = 0;

    virtual ISecurityAgent &GetSecurityAgent() = 0;
    virtual void SetSecurityAgent(std::shared_ptr<ISecurityAgent> securityAgent) = 0;

    virtual ICrossDeviceCommManager &GetCrossDeviceCommManager() = 0;
    virtual void SetCrossDeviceCommManager(std::shared_ptr<ICrossDeviceCommManager> crossDeviceCommManager) = 0;

    virtual IRequestManager &GetRequestManager() = 0;
    virtual void SetRequestManager(std::shared_ptr<IRequestManager> requestManager) = 0;
    virtual IRequestFactory &GetRequestFactory() = 0;
    virtual void SetRequestFactory(std::shared_ptr<IRequestFactory> requestFactory) = 0;

    virtual IncomingMessageHandlerRegistry &GetIncomingMessageHandlerRegistry() = 0;
    virtual void SetIncomingMessageHandlerRegistry(std::shared_ptr<IncomingMessageHandlerRegistry> registry) = 0;

#ifdef ENABLE_TEST
    virtual void Reset() = 0;
#endif

protected:
    SingletonManager() = default;
};

inline ICompanionManager &GetCompanionManager()
{
    return SingletonManager::GetInstance().GetCompanionManager();
}

inline IHostBindingManager &GetHostBindingManager()
{
    return SingletonManager::GetInstance().GetHostBindingManager();
}

inline IMiscManager &GetMiscManager()
{
    return SingletonManager::GetInstance().GetMiscManager();
}

inline ISystemParamManager &GetSystemParamManager()
{
    return SingletonManager::GetInstance().GetSystemParamManager();
}

inline IActiveUserIdManager &GetActiveUserIdManager()
{
    return SingletonManager::GetInstance().GetActiveUserIdManager();
}

inline ISecurityAgent &GetSecurityAgent()
{
    return SingletonManager::GetInstance().GetSecurityAgent();
}

inline ICrossDeviceCommManager &GetCrossDeviceCommManager()
{
    return SingletonManager::GetInstance().GetCrossDeviceCommManager();
}

inline IRequestManager &GetRequestManager()
{
    return SingletonManager::GetInstance().GetRequestManager();
}

inline IRequestFactory &GetRequestFactory()
{
    return SingletonManager::GetInstance().GetRequestFactory();
}

inline IncomingMessageHandlerRegistry &GetIncomingMessageHandlerRegistry()
{
    return SingletonManager::GetInstance().GetIncomingMessageHandlerRegistry();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SINGLETON_MANAGER_H
