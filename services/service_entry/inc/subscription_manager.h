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

#ifndef COMPANION_DEVICE_AUTH_SUBSCRIPTION_MANAGER_H
#define COMPANION_DEVICE_AUTH_SUBSCRIPTION_MANAGER_H

#include <cstdint>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "iremote_object.h"
#include "nocopyable.h"

#include "available_device_subscription.h"
#include "companion_device_auth_types.h"
#include "continuous_auth_subscription.h"
#include "iipc_available_device_status_callback.h"
#include "iipc_continuous_auth_status_callback.h"
#include "iipc_template_status_callback.h"
#include "template_status_subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class SubscriptionManager : public NoCopyable, public std::enable_shared_from_this<SubscriptionManager> {
public:
    SubscriptionManager();
    ~SubscriptionManager() = default;

    void AddAvailableDeviceStatusCallback(int32_t userId,
        const sptr<IIpcAvailableDeviceStatusCallback> &availableDeviceStatusCallback);
    void RemoveAvailableDeviceStatusCallback(
        const sptr<IIpcAvailableDeviceStatusCallback> &availableDeviceStatusCallback);
    void AddTemplateStatusCallback(int32_t userId, const sptr<IIpcTemplateStatusCallback> &templateStatusCallback);
    void RemoveTemplateStatusCallback(const sptr<IIpcTemplateStatusCallback> &templateStatusCallback);
    void AddContinuousAuthStatusCallback(int32_t userId, std::optional<uint64_t> templateId,
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback);
    void RemoveContinuousAuthStatusCallback(const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback);

private:
    void UpdateSubscribeMode();

    std::shared_ptr<AvailableDeviceSubscription> GetOrCreateAvailableDeviceSubscription(UserId userId);
    std::shared_ptr<TemplateStatusSubscription> GetOrCreateTemplateStatusSubscription(UserId userId);
    std::shared_ptr<ContinuousAuthSubscription> GetOrCreateContinuousAuthSubscription(UserId userId,
        std::optional<TemplateId> templateId);

    std::map<UserId, std::shared_ptr<AvailableDeviceSubscription>> availableDeviceSubscriptions_;
    std::map<UserId, std::shared_ptr<TemplateStatusSubscription>> templateStatusSubscriptions_;
    std::map<std::pair<UserId, std::optional<TemplateId>>, std::shared_ptr<ContinuousAuthSubscription>>
        continuousAuthSubscriptions_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SUBSCRIPTION_MANAGER_H
