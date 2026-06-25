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

#ifndef BASE_SERVICE_INITIALIZER_H
#define BASE_SERVICE_INITIALIZER_H

#include <memory>
#include <vector>

#include "nocopyable.h"

#include "common_defines.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SubscriptionManager;
class IncomingMessageHandlerRegistry;
class ICrossDeviceChannel;

class BaseServiceInitializer : public NoCopyable {
public:
    static std::shared_ptr<BaseServiceInitializer> Create();

    std::shared_ptr<SubscriptionManager> GetSubscriptionManager() const;
    const std::vector<BusinessId> &GetHostSupportedBusinessIds() const;
    const std::vector<Capability> &GetHostLocalCapabilities() const;
    const std::vector<BusinessId> &GetCompanionSupportedBusinessIds() const;
    const std::vector<Capability> &GetCompanionLocalCapabilities() const;

protected:
    // Protected constructor for derived classes
    explicit BaseServiceInitializer(std::shared_ptr<SubscriptionManager> subscriptionManager,
        const DeviceCapabilityInfo &deviceCapabilityInfo, bool hostBindingRevokeTokenOnInactive);

    // Virtual initialization methods - can be overridden by derived classes
    virtual bool Initialize();
    virtual bool InitializeTimeKeeper();
    virtual bool InitializeEventManagerAdapter();
    virtual bool InitializeSaManagerAdapter();
    virtual bool InitializeSecurityCommandAdapter();
    virtual bool InitializeSystemParamManager();
    virtual bool InitializeUserIdManager();
    virtual bool InitializeUserAuthFramework();
    virtual bool InitializeRequestManager();
    virtual bool InitializeRequestFactory();
    virtual bool InitializeMiscManager();
    virtual bool InitializeSecurityAgent();
    virtual bool InitializeIncomingMessageHandlerRegistry();
    virtual bool InitializeEventBus();
    virtual bool InitializeChannels();
    virtual bool InitializeCrossDeviceCommManager();
    virtual bool InitializeCompanionManager();
    virtual bool InitializeHostBindingManager();
    virtual bool RegisterHandlers();
    virtual bool StartCrossDeviceCommManager();
    virtual bool InitializeFwkComm();
    virtual bool InitializeExtension();

    // Member variables to store dependencies between initialization steps
    std::shared_ptr<IncomingMessageHandlerRegistry> incomingMessageHandlerRegistryHolder_;
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channelsHolder_;

private:
    using BasicInitFunc = bool (BaseServiceInitializer::*)();
    struct BasicInitStep {
        BasicInitFunc func;
        const char *name;
    };
    static const BasicInitStep BASIC_INIT_TABLE[];
    static const size_t BASIC_INIT_TABLE_SIZE;

    // Execute initialization steps with dependencies (called after basic table)
    bool InitializeDependentSteps();

    std::shared_ptr<SubscriptionManager> subscriptionManagerHolder_;
    std::vector<BusinessId> hostSupportedBusinessIds_;
    std::vector<Capability> hostLocalCapabilities_;
    std::vector<BusinessId> companionSupportedBusinessIds_;
    std::vector<Capability> companionLocalCapabilities_;
    bool hostBindingRevokeTokenOnInactive_ { false };
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // BASE_SERVICE_INITIALIZER_H
