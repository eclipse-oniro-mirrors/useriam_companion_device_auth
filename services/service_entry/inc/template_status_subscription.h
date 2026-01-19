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

#ifndef COMPANION_DEVICE_TEMPLATE_STATUS_SUBSCRIPTION_H
#define COMPANION_DEVICE_TEMPLATE_STATUS_SUBSCRIPTION_H

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "callback_subscription_base.h"
#include "companion_device_auth_types.h"
#include "companion_manager.h"
#include "cross_device_comm_manager.h"
#include "iipc_template_status_callback.h"
#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class SubscriptionManager;

class TemplateStatusSubscription
    : public CallbackSubscriptionBase<IIpcTemplateStatusCallback, TemplateStatusSubscription> {
public:
    static std::shared_ptr<TemplateStatusSubscription> Create(UserId userId,
        std::weak_ptr<SubscriptionManager> subscriptionManager);
    ~TemplateStatusSubscription() = default;

    UserId GetUserId() const;
    std::weak_ptr<TemplateStatusSubscription> GetWeakPtr() override;
    void HandleCompanionStatusChange(const std::vector<CompanionStatus> &companionStatusList);
    void OnCallbackAdded(const sptr<IIpcTemplateStatusCallback> &callback) override;
    void OnCallbackRemoteDied(const sptr<IIpcTemplateStatusCallback> &callback) override;

private:
    TemplateStatusSubscription(UserId userId, std::weak_ptr<SubscriptionManager> subscriptionManager);
    bool Initialize();

    UserId userId_;
    std::weak_ptr<SubscriptionManager> subscriptionManager_;
    std::unique_ptr<Subscription> companionStatusSubscription_;
    std::vector<IpcTemplateStatus> cachedTemplateStatus_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_TEMPLATE_STATUS_SUBSCRIPTION_H
