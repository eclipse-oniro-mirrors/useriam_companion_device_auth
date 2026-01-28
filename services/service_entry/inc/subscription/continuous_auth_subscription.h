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

#ifndef COMPANION_DEVICE_AUTH_CONTINUOUS_AUTH_SUBSCRIPTION_H
#define COMPANION_DEVICE_AUTH_CONTINUOUS_AUTH_SUBSCRIPTION_H

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "callback_subscription_base.h"
#include "companion_device_auth_types.h"
#include "iipc_continuous_auth_status_callback.h"
#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class SubscriptionManager;

class ContinuousAuthSubscription
    : public CallbackSubscriptionBase<IIpcContinuousAuthStatusCallback, ContinuousAuthSubscription> {
public:
    static std::shared_ptr<ContinuousAuthSubscription> Create(UserId userId, std::optional<TemplateId> templateId,
        std::weak_ptr<SubscriptionManager> subscriptionManager);

    ContinuousAuthSubscription(UserId userId, std::optional<TemplateId> templateId,
        std::weak_ptr<SubscriptionManager> subscriptionManager);
    ~ContinuousAuthSubscription() = default;

    UserId GetUserId() const;
    std::optional<TemplateId> GetTemplateId() const;
    std::weak_ptr<ContinuousAuthSubscription> GetWeakPtr() override;
    void OnCallbackAdded(const sptr<IIpcContinuousAuthStatusCallback> &callback) override;
    void OnCallbackRemoteDied(const sptr<IIpcContinuousAuthStatusCallback> &callback) override;

private:
    bool Initialize();
    void HandleCompanionStatusChange(const std::vector<CompanionStatus> &companionStatusList);
    void NotifyAuthStatus(std::optional<Atl> authTrustLevel);

    UserId userId_;
    std::optional<TemplateId> templateId_;
    std::weak_ptr<SubscriptionManager> subscriptionManager_;

    // Subscription to CompanionManager
    std::unique_ptr<Subscription> companionStatusSubscription_;

    // Cached authentication state
    std::optional<Atl> cachedAuthTrustLevel_ { std::nullopt };
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_CONTINUOUS_AUTH_SUBSCRIPTION_H
